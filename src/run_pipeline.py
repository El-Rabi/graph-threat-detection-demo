"""Generate events, extract graph features, and evaluate the detector."""

from pathlib import Path

from generate_events import save_events
from graph_features import extract_session_features
from train import train_and_evaluate


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    data_path = project_root / "data" / "event_edges.csv"
    results_dir = project_root / "results"

    events = save_events(data_path, n_sessions=1200, seed=42)
    features = extract_session_features(events)
    results_dir.mkdir(parents=True, exist_ok=True)
    features.to_csv(results_dir / "session_features.csv", index=False)
    metrics = train_and_evaluate(features, results_dir, seed=42)

    print(f"Generated {features['session_id'].nunique():,} synthetic session graphs")
    print(f"Extracted {features.shape[1] - 2} graph and behavioral features")
    print(f"Test ROC-AUC: {metrics['test_roc_auc']:.3f}")
    print(f"Test F1: {metrics['test_f1']:.3f}")
    print(f"Results saved to {results_dir}")


if __name__ == "__main__":
    main()
