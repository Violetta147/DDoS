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
from pathlib import Path
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
    "Total Fwd Packet": "Tot Fwd Pkts",
    "Total Bwd packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packet": "TotLen Fwd Pkts",
    "Total Length of Bwd Packet": "TotLen Bwd Pkts",

    "Fwd Packet Length Max": "Fwd Pkt Len Max",
    "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean",
    "Fwd Packet Length Std": "Fwd Pkt Len Std",
    "Bwd Packet Length Max": "Bwd Pkt Len Max",
    "Bwd Packet Length Min": "Bwd Pkt Len Min",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Bwd Packet Length Std": "Bwd Pkt Len Std",

    # Abbreviated (83-col) <-> long names (capture / CIC variants)
    "Total Fwd Packets": "Tot Fwd Pkts",
    "Total Backward Packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts",
    "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Flow Bytes/s": "Flow Byts/s",
    "Flow Packets/s": "Flow Pkts/s",
    "Fwd IAT Total": "Fwd IAT Tot",
    "Bwd IAT Total": "Bwd IAT Tot",
    "Fwd Header Length": "Fwd Header Len",
    "Bwd Header Length": "Bwd Header Len",
    "Fwd Packets/s": "Fwd Pkts/s",
    "Bwd Packets/s": "Bwd Pkts/s",
    "Packet Length Min": "Pkt Len Min",
    "Packet Length Max": "Pkt Len Max",
    "Packet Length Mean": "Pkt Len Mean",
    "Packet Length Std": "Pkt Len Std",
    "Packet Length Variance": "Pkt Len Var",
    "FIN Flag Count": "FIN Flag Cnt",
    "SYN Flag Count": "SYN Flag Cnt",
    "RST Flag Count": "RST Flag Cnt",
    "PSH Flag Count": "PSH Flag Cnt",
    "ACK Flag Count": "ACK Flag Cnt",
    "URG Flag Count": "URG Flag Cnt",
    "ECE Flag Count": "ECE Flag Cnt",
    "Average Packet Size": "Pkt Size Avg",
    "Fwd Segment Size Avg": "Fwd Seg Size Avg",
    "Bwd Segment Size Avg": "Bwd Seg Size Avg",
    "Fwd Bytes/Bulk Avg": "Fwd Byts/b Avg",
    "Fwd Packet/Bulk Avg": "Fwd Pkts/b Avg",
    "Fwd Bulk Rate Avg": "Fwd Blk Rate Avg",
    "Bwd Bytes/Bulk Avg": "Bwd Byts/b Avg",
    "Bwd Packet/Bulk Avg": "Bwd Pkts/b Avg",
    "Bwd Bulk Rate Avg": "Bwd Blk Rate Avg",
    "Subflow Fwd Packets": "Subflow Fwd Pkts",
    "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Bwd Packets": "Subflow Bwd Pkts",
    "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "FWD Init Win Bytes": "Init Fwd Win Byts",
    "Bwd Init Win Bytes": "Init Bwd Win Byts",

    # Flag naming variants
    "CWR Flag Count": "CWE Flag Count",
}


DDOS_PROBA_THRESHOLD: float = 0.8


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
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        header_line = f.readline()

    if not header_line.strip():
        raise ValueError(f"CSV header is empty: {csv_path}")

    # Minimal, robust parsing for a plain CSV header.
    cols = [c.strip() for c in header_line.strip().split(",")]
    if not cols or any(c == "" for c in cols):
        raise ValueError(f"CSV header parse failed: {csv_path}")
    return cols


@dataclass(frozen=True)
class TailState:
    offset: int
    remainder: str
    header_cols: Optional[List[str]]
    last_size: int


def init_tail_state(csv_path: str, start_from_beginning: bool) -> TailState:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    size = os.path.getsize(csv_path)
    offset = 0 if start_from_beginning else size
    print(
        f"Debug: Tail init (start_from_beginning={start_from_beginning}) "
        f"offset={offset} size={size}"
    )
    return TailState(offset=offset, remainder="", header_cols=None, last_size=size)


def read_appended_complete_lines(csv_path: str, state: TailState) -> Tuple[TailState, List[str]]:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    current_size = os.path.getsize(csv_path)
    offset = state.offset
    remainder = state.remainder
    header_cols = state.header_cols

    if current_size < state.last_size:
        print(
            f"Debug: CSV truncated/recreated ({state.last_size} -> {current_size}); resetting tail"
        )
        offset = 0
        remainder = ""
        header_cols = None

    if offset > current_size:
        print(f"Debug: Offset beyond file size; resetting offset ({offset} -> 0)")
        offset = 0
        remainder = ""

    if current_size == offset:
        return TailState(offset=offset, remainder=remainder, header_cols=header_cols, last_size=current_size), []

    with open(csv_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        f.seek(offset)
        new_data = f.read()
        new_offset = f.tell()

    combined = remainder + new_data
    if not combined:
        return TailState(offset=new_offset, remainder="", header_cols=header_cols, last_size=current_size), []

    # Keep only complete lines; hold the last partial line in remainder.
    parts = combined.splitlines(keepends=True)
    complete_lines: List[str] = []
    new_remainder = ""
    for part in parts:
        if part.endswith("\n") or part.endswith("\r"):
            line = part.rstrip("\r\n")
            if line.strip():
                complete_lines.append(line)
        else:
            new_remainder = part

    next_state = TailState(
        offset=new_offset,
        remainder=new_remainder,
        header_cols=header_cols,
        last_size=current_size,
    )
    return next_state, complete_lines


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

    # Make aliasing header-style agnostic by also allowing reverse mappings.
    # Example:
    #   long_name <- short_name  (existing mapping)
    #   short_name <- long_name  (reverse mapping)
    alias_pairs: Dict[str, str] = dict(column_aliases)
    for expected, actual in list(column_aliases.items()):
        if actual not in alias_pairs:
            alias_pairs[actual] = expected

    # Apply aliases transitively (create expected columns from available ones).
    # Some models use different naming conventions where aliases can be chained:
    #   A <- B <- C
    # We iterate until no new columns are created (or until bounded by alias count).
    max_passes = max(len(alias_pairs), 1)
    for _ in range(max_passes):
        created_any = False
        for expected, actual in alias_pairs.items():
            if expected not in df_work.columns and actual in df_work.columns:
                df_work[expected] = df_work[actual]
                created_any = True
                print(f"Debug: Alias applied: {expected} <- {actual}")
        if not created_any:
            break

    # Derive select model features when possible.
    # Some trained CIC-style datasets include extra convenience columns.
    if "Total TCP Flow Time" in schema.feature_names and "Total TCP Flow Time" not in df_work.columns:
        if "Protocol" in df_work.columns and "Flow Duration" in df_work.columns:
            proto = pd.to_numeric(df_work["Protocol"], errors="coerce")
            flow_dur = pd.to_numeric(df_work["Flow Duration"], errors="coerce")
            df_work["Total TCP Flow Time"] = np.where(proto == 6, flow_dur, 0.0)
            print("Debug: Derived: Total TCP Flow Time <- Flow Duration (TCP only)")

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
    if not schema.has_predict_proba:
        raise ValueError(
            "predict_proba is required for thresholding but is not available on this model"
        )

    p = np.asarray(model.predict_proba(X))
    if p.ndim != 2:
        raise ValueError(f"Unexpected predict_proba shape: {p.shape}")

    if p.shape[1] == 2:
        proba = p[:, 1]
    else:
        proba = p.max(axis=1)

    pred = (proba >= DDOS_PROBA_THRESHOLD).astype(int)
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
        self.remainder = ""

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
                self.remainder = ""
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

            combined = self.remainder + new_data
            parts = combined.splitlines(keepends=True)
            lines: List[str] = []
            new_remainder = ""
            for part in parts:
                if part.endswith("\n") or part.endswith("\r"):
                    line = part.rstrip("\r\n")
                    if line.strip():
                        lines.append(line)
                else:
                    new_remainder = part

            self.remainder = new_remainder
            if lines:
                print(
                    f"Debug: Read {len(lines)} complete line(s) (offset={self.offset} remainder_len={len(self.remainder)})"
                )
                self.on_lines(lines)
        except Exception as exc:
            print(f"⚠️ Error reading CSV: {type(exc).__name__}: {exc}")


def run_watcher(
    csv_path: str,
    batch_size: int,
    poll: bool,
    poll_interval_s: float,
    start_from_beginning: bool,
    model: SklearnBinaryClassifier,
    schema: ModelSchema,
) -> None:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    buffer: List[str] = []
    tail_state = init_tail_state(csv_path, start_from_beginning)

    def process_lines(lines: List[str]) -> None:
        nonlocal buffer
        buffer.extend(lines)
        if len(buffer) >= batch_size:
            flush_buffer()

    def flush_buffer() -> None:
        nonlocal buffer
        nonlocal tail_state
        if not buffer:
            return

        local_lines = buffer.copy()
        buffer = []

        if tail_state.header_cols is None:
            tail_state = TailState(
                offset=tail_state.offset,
                remainder=tail_state.remainder,
                header_cols=read_header(csv_path),
                last_size=tail_state.last_size,
            )
            print(f"Debug: Loaded CSV header cols={len(tail_state.header_cols)}")

        header_cols = tail_state.header_cols
        if header_cols is None:
            raise RuntimeError("Header columns not initialized")

        df_new = lines_to_frame(local_lines, header_cols)
        if df_new.empty:
            return

        print(f"Debug: Processing {len(df_new)} new row(s)")
        X = prepare_features(df_new, schema, COLUMN_ALIASES)
        pred, proba = predict_batch(model, schema, X)
        print_batch_summary(pred, proba)

    if poll or not HAS_WATCHDOG:
        print("Debug: Running in polling mode")
        while True:
            tail_state, lines = read_appended_complete_lines(csv_path, tail_state)
            if lines:
                print(
                    f"Debug: Tail read complete_lines={len(lines)} offset={tail_state.offset} "
                    f"remainder_len={len(tail_state.remainder)}"
                )
                process_lines(lines)

            time.sleep(poll_interval_s)
    else:
        print("Debug: Running with watchdog observer")
        handler = CSVAppendHandler(csv_path, process_lines)
        # Initialize handler to tail from desired position.
        handler.offset = 0 if start_from_beginning else os.path.getsize(csv_path)
        handler.file_size = os.path.getsize(csv_path)
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
    parser = argparse.ArgumentParser(
        description="Real-time DDoS Detection System (RandomForest watcher)",
        epilog=(
            "Examples:\n"
            "  python detection_system.py\n"
            "  python detection_system.py data/live_flow.csv\n"
            "  python detection_system.py data/live_flow.csv models/random_forest_model.joblib\n"
            "  python detection_system.py live_flow.csv random_forest_model.joblib 50 1 --poll\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Positional args (friendly)
    # NOTE: Use distinct dest names to avoid clobbering the flag args.
    parser.add_argument("csv_path_pos", nargs="?", help="CSV path (default: data/live_flow.csv)")
    parser.add_argument(
        "model_path_pos",
        nargs="?",
        help="Model path (default: models/random_forest_model.joblib)",
    )
    parser.add_argument("batch_size_pos", nargs="?", type=int, help="Batch size (default: 1)")
    parser.add_argument(
        "poll_interval_s_pos",
        nargs="?",
        type=float,
        help="Polling interval seconds (default: 1)",
    )

    # Flag args (explicit)
    parser.add_argument("--csv-path", dest="csv_path_opt", default=None, help="CSV path produced by sniffer/export")
    parser.add_argument("--model-path", dest="model_path_opt", default=None, help="Path to RandomForest joblib model")
    parser.add_argument("--batch-size", dest="batch_size_opt", default=None, type=int, help="Batch size for inference")
    parser.add_argument("--poll", action="store_true", help="Force polling mode instead of watchdog")
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Process existing rows from the beginning (default: start at end and only process new appended rows)",
    )
    parser.add_argument(
        "--poll-interval-s",
        dest="poll_interval_s_opt",
        default=None,
        type=float,
        help="Polling interval in seconds",
    )
    args, unknown = parser.parse_known_args()
    if unknown:
        print(f"Debug: Ignoring unknown args (likely from Jupyter/IPython): {unknown}")

    def resolve_existing_path(path_value: str, fallback_dir: str) -> str:
        path_str = str(path_value).strip()
        if not path_str:
            raise ValueError("Empty path")

        if os.path.exists(path_str):
            return path_str

        alt = os.path.join(fallback_dir, path_str)
        if os.path.exists(alt):
            print(f"Debug: Resolved path '{path_str}' -> '{alt}'")
            return alt

        raise FileNotFoundError(f"Path not found: {path_str} (also tried: {alt})")

    default_csv = os.path.join("data", "live_flow.csv")
    default_model = os.path.join("models", "random_forest_model.joblib")

    csv_path_value = (
        args.csv_path_opt
        if args.csv_path_opt is not None
        else (args.csv_path_pos if args.csv_path_pos is not None else default_csv)
    )
    model_path_value = (
        args.model_path_opt
        if args.model_path_opt is not None
        else (args.model_path_pos if args.model_path_pos is not None else default_model)
    )
    batch_size_value = (
        int(args.batch_size_opt)
        if args.batch_size_opt is not None
        else (int(args.batch_size_pos) if args.batch_size_pos is not None else 1)
    )
    poll_interval_value = (
        float(args.poll_interval_s_opt)
        if args.poll_interval_s_opt is not None
        else (float(args.poll_interval_s_pos) if args.poll_interval_s_pos is not None else 1.0)
    )

    csv_path = resolve_existing_path(csv_path_value, "data")
    model_path = resolve_existing_path(model_path_value, "models")

    model = load_model(model_path)
    schema = infer_schema(model)
    run_watcher(
        csv_path,
        batch_size_value,
        args.poll,
        poll_interval_value,
        bool(args.from_start),
        model,
        schema,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}")
        sys.exit(1)
