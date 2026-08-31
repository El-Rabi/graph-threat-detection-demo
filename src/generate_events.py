"""Generate reproducible synthetic endpoint event graphs."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


BENIGN_TEMPLATES = [
    [("explorer.exe", "browser.exe", "process"), ("browser.exe", "trusted_api", "network")],
    [("outlook.exe", "pdf_reader.exe", "process"), ("pdf_reader.exe", "document.pdf", "file")],
    [("python.exe", "analysis.csv", "file"), ("python.exe", "local_database", "network")],
    [("teams.exe", "browser.exe", "process"), ("browser.exe", "company_portal", "network")],
    [("backup.exe", "archive.zip", "file"), ("backup.exe", "backup_server", "network")],
]


def generate_event_data(n_sessions: int = 1200, seed: int = 42) -> pd.DataFrame:
    """Return edge rows for benign and simplified attack sessions."""
    if n_sessions < 100:
        raise ValueError("n_sessions must be at least 100")
    rng = np.random.default_rng(seed)
    rows: list[dict[str, object]] = []

    for index in range(n_sessions):
        session_id = f"SESSION-{index + 1:05d}"
        is_attack = bool(rng.random() < 0.30)
        label = "attack" if is_attack else "benign"

        # Some compromised sessions are deliberately stealthy, while a small
        # number of benign sessions contain administrator activity that looks
        # suspicious. This overlap prevents a trivially separable benchmark.
        attack_shaped_activity = is_attack
        if is_attack and rng.random() < 0.13:
            attack_shaped_activity = False
        elif not is_attack and rng.random() < 0.06:
            attack_shaped_activity = True

        if attack_shaped_activity:
            edges = [
                ("outlook.exe", "powershell.exe", "process", 0, 0, 1),
                ("powershell.exe", "payload.tmp", "file", 0, 0, 1),
                ("powershell.exe", "rundll32.exe", "process", 0, 0, 0),
                ("rundll32.exe", "curl.exe", "process", 0, 0, 0),
                ("curl.exe", "external_host", "network", int(rng.integers(80_000, 900_000)), 1, 0),
            ]
            if rng.random() < 0.45:
                edges.insert(3, ("rundll32.exe", "credential_store", "file", 0, 0, 0))
        else:
            template = BENIGN_TEMPLATES[int(rng.integers(0, len(BENIGN_TEMPLATES)))]
            edges = []
            for source, target, event_type in template:
                is_external = int(target == "trusted_api")
                bytes_out = int(rng.integers(2_000, 65_000)) if event_type == "network" else 0
                edges.append((source, target, event_type, bytes_out, is_external, 0))
            if rng.random() < 0.35:
                edges.append((template[-1][1], "cache.tmp", "file", 0, 0, 0))

        for step, (source, target, event_type, bytes_out, external, encoded) in enumerate(edges, 1):
            rows.append(
                {
                    "session_id": session_id,
                    "step": step,
                    "source": source,
                    "target": target,
                    "event_type": event_type,
                    "bytes_out": bytes_out,
                    "is_external": external,
                    "encoded_command": encoded,
                    "label": label,
                }
            )

    return pd.DataFrame(rows)


def save_events(output_path: Path, n_sessions: int = 1200, seed: int = 42) -> pd.DataFrame:
    data = generate_event_data(n_sessions=n_sessions, seed=seed)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data.to_csv(output_path, index=False)
    return data
