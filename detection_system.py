"""Real-time DDoS Detection System (RandomForest CSV watcher).

Watches `data/live_flow.csv` produced by the sniffer and runs inference using
`models/random_forest_model.joblib`.

Usage:
  python detection_system.py --csv-path data/live_flow.csv
  python detection_system.py --csv-path data/live_flow.csv --poll

Notes:
- If the model expects extra columns not present in the CSV (e.g. "Attempted Category"),
  they are created as 0.0.
- This script prints debug messages to make failures obvious.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from io import StringIO
from typing import Dict, List, Optional, Protocol, Tuple

import joblib
import numpy as np
import pandas as pd
from colorama import Fore, Style, init as colorama_init

colorama_init()

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


class SklearnBinaryClassifier(Protocol):
    feature_names_in_: np.ndarray

    def predict(self, X: pd.DataFrame) -> np.ndarray:  # noqa: N802
        ...

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:  # noqa: N802
        ...


@dataclass(frozen=True)
class ModelSchema:
    feature_names: List[str]
    has_predict_proba: bool


COLUMN_ALIASES: Dict[str, str] = {
    # model_expected: csv_actual
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
}


def load_model(model_path: str) -> SklearnBinaryClassifier:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    print(f"Debug: Loading model: {model_path}")
    model = joblib.load(model_path)
    print(f"Debug: Model type: {type(model)}")

    return model  # type: ignore[return-value]


def infer_schema(model: SklearnBinaryClassifier) -> ModelSchema:
    feature_names_in = getattr(model, "feature_names_in_", None)
    if feature_names_in is None:
        raise ValueError(
            "Model does not expose feature_names_in_. "
            "Re-train and save the model with scikit-learn >= 1.0 (fit with a DataFrame)."
        )

    feature_names = [str(x) for x in list(feature_names_in)]
    has_predict_proba = callable(getattr(model, "predict_proba", None))

    print(f"Debug: Model expects {len(feature_names)} feature columns")
    print(f"Debug: predict_proba available: {has_predict_proba}")

    return ModelSchema(feature_names=feature_names, has_predict_proba=has_predict_proba)


def read_header(csv_path: str) -> List[str]:
    header_df = pd.read_csv(csv_path, nrows=0)
    cols = [str(c).strip() for c in header_df.columns]
    if not cols:
        raise ValueError(f"CSV has no columns: {csv_path}")
    return cols


def lines_to_frame(lines: List[str], header_cols: List[str]) -> pd.DataFrame:
    if not lines:
        raise ValueError("No lines to parse")

    first_col = header_cols[0]
    if lines and lines[0].split(",")[0].strip() == first_col:
        lines = lines[1:]

    if not lines:
        return pd.DataFrame(columns=header_cols)

    df_new = pd.read_csv(StringIO("\n".join(lines)), header=None)

    if len(df_new.columns) != len(header_cols):
        raise ValueError(f"Column mismatch: expected {len(header_cols)}, got {len(df_new.columns)}")

    df_new.columns = header_cols
    df_new.columns = df_new.columns.astype(str).str.strip()
    return df_new


def prepare_features(
    df_in: pd.DataFrame,
    schema: ModelSchema,
    column_aliases: Dict[str, str],
) -> pd.DataFrame:
    df_work = df_in.copy()

    # Apply aliases (create expected columns from available ones)
    for expected, actual in column_aliases.items():
        if expected not in df_work.columns and actual in df_work.columns:
            df_work[expected] = df_work[actual]
            print(f"Debug: Alias applied: {expected} <- {actual}")

    missing = [c for c in schema.feature_names if c not in df_work.columns]
    if missing:
        print("Debug: Creating missing feature columns as 0.0:")
        for c in missing:
            print(f"  - {c}")
            df_work[c] = 0.0

    X = df_work[schema.feature_names].copy()

    # Coerce to numeric and fill NaNs with 0.0 for streaming reliability.
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    nan_cells = int(X.isna().sum().sum())
    if nan_cells > 0:
        print(f"Debug: NaNs found after coercion: {nan_cells} (filling with 0.0)")
        X = X.fillna(0.0)

    if not np.isfinite(X.to_numpy()).all():
        raise ValueError("Non-finite values (inf/-inf) present in prepared features")

    return X


def predict_batch(
    model: SklearnBinaryClassifier,
    schema: ModelSchema,
    X: pd.DataFrame,
) -> Tuple[np.ndarray, Optional[np.ndarray]]:
    pred = np.asarray(model.predict(X)).astype(int)

    proba: Optional[np.ndarray] = None
    if schema.has_predict_proba:
        p = np.asarray(model.predict_proba(X))
        if p.ndim != 2:
            raise ValueError(f"Unexpected predict_proba shape: {p.shape}")
        if p.shape[1] == 2:
            proba = p[:, 1]
        else:
            proba = p.max(axis=1)

    return pred, proba


def print_batch_summary(pred: np.ndarray, proba: Optional[np.ndarray]) -> None:
    if pred.size == 0:
        return

    unique, counts = np.unique(pred, return_counts=True)
    summary = {int(k): int(v) for k, v in zip(unique.tolist(), counts.tolist())}

    if summary.get(1, 0) > 0:
        msg = f"ALERT: predicted_attack={summary.get(1, 0)} / {pred.size}"
        if proba is not None:
            msg += f"  max_proba={float(np.max(proba)):.3f}"
        print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
    else:
        msg = f"OK: predicted_attack=0 / {pred.size}"
        if proba is not None:
            msg += f"  max_proba={float(np.max(proba)):.3f}"
        print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")


class CSVAppendHandler(FileSystemEventHandler):
    def __init__(self, csv_path: str, on_lines: Callable[[List[str]], None]):
        super().__init__()
        self.csv_path = csv_path
        self.offset = 0
        self.file_size = 0
        self.on_lines = on_lines

    def on_modified(self, event):
        if event.src_path != os.path.abspath(self.csv_path):
            return
        self._process_new_lines()

    def on_created(self, event):
        if event.src_path != os.path.abspath(self.csv_path):
            return
        print("Debug: CSV created; resetting offset")
        self.offset = 0
        self.file_size = 0

    def _process_new_lines(self) -> None:
        try:
            current_size = os.path.getsize(self.csv_path)
            if current_size < self.file_size:
                print(f"Debug: CSV truncated/recreated ({self.file_size} -> {current_size}); resetting offset")
                self.offset = 0
            self.file_size = current_size

            if self.offset > current_size:
                print(f"Debug: Offset beyond file size; resetting offset ({self.offset} -> 0)")
                self.offset = 0

            with open(self.csv_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.offset)
                new_data = f.read()
                new_offset = f.tell()

            if new_offset == self.offset:
                return

            self.offset = new_offset

            if not new_data.strip():
                return

            lines = [l for l in new_data.splitlines() if l.strip()]
            if lines:
                print(f"Debug: Read {len(lines)} new line(s) (offset={self.offset})")
            self.on_lines(lines)
        except Exception as exc:
            print(f"⚠️ Error reading CSV: {type(exc).__name__}: {exc}")


def run_watcher(
    csv_path: str,
    batch_size: int,
    poll: bool,
    poll_interval_s: float,
    model: SklearnBinaryClassifier,
    schema: ModelSchema,
) -> None:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    buffer: List[str] = []

    def process_lines(lines: List[str]) -> None:
        nonlocal buffer
        buffer.extend(lines)
        if len(buffer) >= batch_size:
            flush_buffer()

    def flush_buffer() -> None:
        nonlocal buffer
        if not buffer:
            return

        local_lines = buffer.copy()
        buffer = []

        header_cols = read_header(csv_path)
        df_new = lines_to_frame(local_lines, header_cols)
        if df_new.empty:
            return

        print(f"Debug: Processing {len(df_new)} new row(s)")
        X = prepare_features(df_new, schema, COLUMN_ALIASES)
        pred, proba = predict_batch(model, schema, X)
        print_batch_summary(pred, proba)

    if poll or not HAS_WATCHDOG:
        print("Debug: Running in polling mode")
        offset = 0
        last_size = 0
        while True:
            if os.path.exists(csv_path):
                current_size = os.path.getsize(csv_path)
                if current_size < last_size:
                    print(f"Debug: CSV truncated/recreated ({last_size} -> {current_size}); resetting offset")
                    offset = 0
                last_size = current_size

                if current_size > offset:
                    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(offset)
                        new_data = f.read()
                        new_offset = f.tell()

                    if new_offset > offset:
                        lines = [l for l in new_data.splitlines() if l.strip()]
                        if lines:
                            process_lines(lines)
                        offset = new_offset

            time.sleep(poll_interval_s)
    else:
        print("Debug: Running with watchdog observer")
        handler = CSVAppendHandler(csv_path, process_lines)
        observer = Observer()
        observer.schedule(handler, path=os.path.dirname(os.path.abspath(csv_path)) or ".", recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-time DDoS Detection System (RandomForest watcher)")
    parser.add_argument("--csv-path", required=True, help="CSV path produced by sniffer/export")
    parser.add_argument("--model-path", required=True, help="Path to RandomForest joblib model")
    parser.add_argument("--batch-size", type=int, required=True, help="Batch size for inference")
    parser.add_argument("--poll", action="store_true", help="Force polling mode instead of watchdog")
    parser.add_argument("--poll-interval-s", type=float, required=True, help="Polling interval in seconds")
    args, unknown = parser.parse_known_args()
    if unknown:
        print(f"Debug: Ignoring unknown args (likely from Jupyter/IPython): {unknown}")

    model = load_model(args.model_path)
    schema = infer_schema(model)
    run_watcher(args.csv_path, args.batch_size, args.poll, args.poll_interval_s, model, schema)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}")
        sys.exit(1)
