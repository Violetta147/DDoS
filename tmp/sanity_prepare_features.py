from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from archive.detection_system import COLUMN_ALIASES, ModelSchema, prepare_features


def main() -> None:
    schema = ModelSchema(
        feature_names=["Total Fwd Packets", "Flow Bytes/s", "Fwd Header Length"],
        has_predict_proba=True,
    )

    df_short = pd.DataFrame(
        [
            {
                "Tot Fwd Pkts": 1,
                "Flow Byts/s": 100.0,
                "Fwd Header Len": 40,
            }
        ]
    )
    df_long = pd.DataFrame(
        [
            {
                "Total Fwd Packets": 1,
                "Flow Bytes/s": 100.0,
                "Fwd Header Length": 40,
            }
        ]
    )

    x1 = prepare_features(df_short, schema, COLUMN_ALIASES)
    x2 = prepare_features(df_long, schema, COLUMN_ALIASES)

    print("x1", x1.iloc[0].to_dict())
    print("x2", x2.iloc[0].to_dict())


if __name__ == "__main__":
    main()
