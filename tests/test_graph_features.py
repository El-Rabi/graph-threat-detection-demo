"""Tests for event generation and graph feature extraction."""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from generate_events import generate_event_data  # noqa: E402
from graph_features import extract_session_features  # noqa: E402


class GraphFeatureTests(unittest.TestCase):
    def test_one_feature_row_is_created_per_session(self) -> None:
        events = generate_event_data(n_sessions=150, seed=4)
        features = extract_session_features(events)
        self.assertEqual(len(features), 150)
        self.assertSetEqual(set(features["label"]), {"benign", "attack"})

    def test_attack_sessions_include_external_paths(self) -> None:
        events = generate_event_data(n_sessions=200, seed=9)
        features = extract_session_features(events)
        attacks = features[features["label"] == "attack"]
        self.assertGreater(attacks["has_external_path"].mean(), 0.70)
        self.assertGreater((attacks["suspicious_relationship_count"] >= 3).mean(), 0.70)


if __name__ == "__main__":
    unittest.main()
