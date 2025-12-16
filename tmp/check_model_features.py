from __future__ import annotations

from pathlib import Path
from typing import Iterable

import sys

import joblib

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

import capture.utils as capture_utils


def _resolve_aliases_once(cols: set[str], aliases: dict[str, str]) -> tuple[set[str], bool]:
    created_any = False
    next_cols = set(cols)
    for expected, actual in aliases.items():
        if expected not in next_cols and actual in next_cols:
            next_cols.add(expected)
            created_any = True
    return next_cols, created_any


def _resolve_aliases(cols: set[str], aliases: dict[str, str]) -> set[str]:
    current = set(cols)
    max_passes = max(len(aliases), 1)
    for _ in range(max_passes):
        current, changed = _resolve_aliases_once(current, aliases)
        if not changed:
            return current
    return current


def _to_list(values: Iterable[str]) -> list[str]:
    return [str(v) for v in values]


def main() -> None:
    capture_utils.init_feature_names()
    csv_cols: list[str] = list(capture_utils.FEATURE_NAMES or [])

    model_path = Path("models") / "random_forest_model.joblib"
    model = joblib.load(model_path)

    print(f"MODEL_TYPE: {type(model)}")
    n_features_in = getattr(model, "n_features_in_", None)
    feature_names_in = getattr(model, "feature_names_in_", None)

    print(f"n_features_in_: {n_features_in}")
    print(f"has_feature_names_in_: {feature_names_in is not None}")
    print(f"csv_cols_count: {len(csv_cols)}")

    if feature_names_in is None:
        print("Model does not expose feature_names_in_.")
        return

    model_features: list[str] = _to_list(feature_names_in)
    print(f"model_features_count: {len(model_features)}")
    print(f"model_features_all: {model_features}")
    print(f"model_features_first10: {model_features[:10]}")
    print(f"model_features_last10: {model_features[-10:]}")

    missing_in_csv = [name for name in model_features if name not in csv_cols]
    extra_in_csv = [name for name in csv_cols if name not in model_features]

    print(f"missing_in_csv_count: {len(missing_in_csv)}")
    print(f"extra_in_csv_count: {len(extra_in_csv)}")
    print(f"missing_in_csv_first30: {missing_in_csv[:30]}")
    print(f"extra_in_csv_first30: {extra_in_csv[:30]}")

    try:
        from detection_system import COLUMN_ALIASES

        resolved_cols = _resolve_aliases(set(csv_cols), COLUMN_ALIASES)
        missing_after_alias = [name for name in model_features if name not in resolved_cols]
        print(f"missing_after_alias_count: {len(missing_after_alias)}")
        print(f"missing_after_alias_all: {missing_after_alias}")
    except Exception as exc:
        print(f"Could not import detection_system aliases: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
