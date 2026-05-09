"""Behaviour-graph renderer — Phase 10 swims into the new temporal swimlane.

Historically this module owned the hand-rolled layered layout. As of Phase 10
the analyst-facing graph is the strict 4-lane Temporal Swimlane (see
``swimlane_view.py``); we re-export it here as ``GraphView`` so every existing
caller (MainWindow, the screenshot script, the smoke tests) keeps working
unchanged.
"""
from analystbridge.ui.swimlane_view import (
    LANES,
    NODE_H,
    NODE_W,
    SwimlaneView as GraphView,
    ZONE_BY_KIND,
    compute_layout,
    route_manhattan,
)

__all__ = [
    "GraphView",
    "LANES",
    "NODE_H",
    "NODE_W",
    "ZONE_BY_KIND",
    "compute_layout",
    "route_manhattan",
]
