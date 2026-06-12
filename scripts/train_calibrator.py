import json
import os
import pickle
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from sklearn.isotonic import IsotonicRegression
from src.alert_parser import parse_alert_directory
from src.misp_enricher import enrich_alert
from src.mitre_mapper import map_ttps
from src.triage_engine import _compute_weighted_score, _load_scoring_config

LABELED_ALERTS = {
    "ALERT-2025-001-CLEAN": 0.0,
    "ALERT-2025-002-CLEAN": 0.0,
    "ALERT-2025-003-SUSP": 0.8,
    "ALERT-2025-004-SUSP": 0.9,
    "ALERT-2025-005-SUSP": 0.6,
}


def main():
    config = _load_scoring_config(
        os.path.join(PROJECT_ROOT, "src", "scoring_config.json")
    )
    if config is None:
        print("ERROR: Could not load scoring_config.json", file=sys.stderr)
        sys.exit(1)

    alerts = parse_alert_directory(os.path.join(PROJECT_ROOT, "test_corpus"))
    raw_scores = []
    labels = []
    for alert in alerts:
        aid = alert["alert_id"]
        if aid not in LABELED_ALERTS:
            continue
        ttps = map_ttps(alert)
        misp = enrich_alert(alert)
        composite, _ = _compute_weighted_score(alert, ttps, misp, config)
        raw_scores.append(composite)
        labels.append(LABELED_ALERTS[aid])

    ir = IsotonicRegression()
    ir.fit(raw_scores, labels)

    out_path = os.path.join(PROJECT_ROOT, "calibrator.pkl")
    with open(out_path, "wb") as f:
        pickle.dump(ir, f)
    print(f"Calibrator saved to {out_path}")
    print(f"  Raw scores:  {raw_scores}")
    print(f"  Labels:      {labels}")
    print(f"  Calibrated:  {ir.transform(raw_scores).tolist()}")


if __name__ == "__main__":
    main()
