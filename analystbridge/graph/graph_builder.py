"""Build a behavior graph from a sample's events.

Returns a `networkx.MultiDiGraph` where:
  - nodes are processes / files / domains / ips / urls / registry / yara / api / module / memory
  - edges are events: each carries event_id, ts, action, event_type
The UI's QGraphicsScene renderer (Phase 4+) consumes this.
"""
from __future__ import annotations

from typing import Iterable

import networkx as nx

from analystbridge.core.event_row import EventRow


def _process_label(actor: dict) -> str:
    name = actor.get("name") or "?"
    pid = actor.get("pid")
    return f"{name}\nPID: {pid}" if pid else name


def _target_label(target: dict, target_type: str | None) -> str:
    if target_type == "process":
        return _process_label(target)
    if target_type == "file":
        return target.get("file_path") or target.get("path") or "?"
    if target_type in {"domain", "ip", "url"}:
        return target.get("url") or target.get("domain") or target.get("remote_ip") or "?"
    if target_type == "registry":
        key = target.get("key") or "?"
        value_name = target.get("value_name")
        return f"{key}\\{value_name}" if value_name else key
    if target_type == "yara":
        return target.get("rule") or "?"
    if target_type == "api":
        return target.get("api") or "?"
    if target_type == "module":
        return target.get("name") or target.get("path") or "?"
    if target_type == "memory":
        return target.get("name") or target.get("path") or "?"
    return target.get("name") or target.get("path") or "?"


class GraphBuilder:
    def build(self, events: Iterable[EventRow]) -> nx.MultiDiGraph:
        g = nx.MultiDiGraph()

        for e in events:
            actor = e.actor
            target = e.target

            if e.actor_id and e.actor_id not in g:
                g.add_node(
                    e.actor_id,
                    kind="process",
                    label=_process_label(actor),
                    pid=actor.get("pid"),
                    name=actor.get("name"),
                    path=actor.get("path"),
                )

            if e.target_id and e.target_id not in g:
                g.add_node(
                    e.target_id,
                    kind=e.target_type or "unknown",
                    label=_target_label(target, e.target_type),
                    **{k: v for k, v in target.items() if v is not None},
                )

            if e.actor_id and e.target_id:
                g.add_edge(
                    e.actor_id,
                    e.target_id,
                    event_id=e.event_id,
                    ts=e.ts,
                    action=e.action,
                    event_type=e.event_type,
                )

        return g

    @staticmethod
    def stats(g: nx.MultiDiGraph) -> dict:
        kinds: dict[str, int] = {}
        for _, data in g.nodes(data=True):
            kind = data.get("kind", "unknown")
            kinds[kind] = kinds.get(kind, 0) + 1
        return {
            "nodes": g.number_of_nodes(),
            "edges": g.number_of_edges(),
            "by_kind": kinds,
        }
