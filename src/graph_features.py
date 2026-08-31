"""Convert endpoint edge rows into session-level graph features."""

from __future__ import annotations

from collections import defaultdict, deque

import pandas as pd


SUSPICIOUS_PROCESSES = {"powershell.exe", "rundll32.exe", "curl.exe", "wscript.exe"}
SUSPICIOUS_RELATIONSHIPS = {
    ("outlook.exe", "powershell.exe"),
    ("powershell.exe", "rundll32.exe"),
    ("rundll32.exe", "curl.exe"),
}


def _has_path(adjacency: dict[str, set[str]], starts: set[str], goal: str) -> int:
    queue = deque(starts)
    visited = set(starts)
    while queue:
        node = queue.popleft()
        if node == goal:
            return 1
        for neighbor in adjacency.get(node, set()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return 0


def _longest_simple_path(adjacency: dict[str, set[str]], nodes: set[str]) -> int:
    """Return the longest simple path length; graphs here are intentionally small."""
    def visit(node: str, visited: set[str]) -> int:
        lengths = [visit(neighbor, visited | {neighbor}) for neighbor in adjacency.get(node, set()) if neighbor not in visited]
        return 0 if not lengths else 1 + max(lengths)

    return max((visit(node, {node}) for node in nodes), default=0)


def extract_session_features(events: pd.DataFrame) -> pd.DataFrame:
    """Aggregate edge rows into structural and behavioral graph features."""
    feature_rows: list[dict[str, object]] = []

    for session_id, group in events.groupby("session_id", sort=True):
        nodes = set(group["source"]) | set(group["target"])
        adjacency: dict[str, set[str]] = defaultdict(set)
        out_degree: dict[str, int] = defaultdict(int)
        relationships = set()
        for row in group.itertuples(index=False):
            adjacency[row.source].add(row.target)
            out_degree[row.source] += 1
            relationships.add((row.source, row.target))

        edge_count = len(group)
        possible_edges = max(len(nodes) * (len(nodes) - 1), 1)
        feature_rows.append(
            {
                "session_id": session_id,
                "node_count": len(nodes),
                "edge_count": edge_count,
                "graph_density": edge_count / possible_edges,
                "max_out_degree": max(out_degree.values(), default=0),
                "longest_path": _longest_simple_path(adjacency, nodes),
                "unique_event_types": group["event_type"].nunique(),
                "external_edge_count": int(group["is_external"].sum()),
                "encoded_command_count": int(group["encoded_command"].sum()),
                "outbound_bytes": int(group["bytes_out"].sum()),
                "suspicious_process_count": len(nodes & SUSPICIOUS_PROCESSES),
                "suspicious_relationship_count": len(relationships & SUSPICIOUS_RELATIONSHIPS),
                "has_external_path": _has_path(adjacency, {"outlook.exe", "explorer.exe"}, "external_host"),
                "label": group["label"].iloc[0],
            }
        )
    return pd.DataFrame(feature_rows)
