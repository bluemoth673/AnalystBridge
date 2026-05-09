"""Boot the GUI, run Load Demo, save dashboard + graph screenshots.

Run from the repo root with:
    python scripts/screenshot.py
    python scripts/screenshot.py --offscreen      # use Qt offscreen plugin
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if "--offscreen" in sys.argv:
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    sys.argv.remove("--offscreen")

from PySide6.QtWidgets import QApplication

from analystbridge.main_window import MainWindow


def _pump(app: QApplication, n: int = 8) -> None:
    for _ in range(n):
        app.processEvents()


def main() -> int:
    out_dir = Path("exports")
    out_dir.mkdir(parents=True, exist_ok=True)

    app = QApplication.instance() or QApplication(sys.argv)
    w = MainWindow()
    w.resize(1600, 1000)
    w.show()
    _pump(app)
    w.on_load_demo()
    _pump(app)

    dashboard_path = out_dir / "ui_preview_dashboard.png"
    w.grab().save(str(dashboard_path), "PNG")
    print(f"Saved {dashboard_path}")

    w.on_nav("Graph")
    _pump(app)
    w.graph_view.fit_view()
    _pump(app)
    graph_path = out_dir / "ui_preview_graph.png"
    w.grab().save(str(graph_path), "PNG")
    print(f"Saved {graph_path}")

    # Optional: also render the Cuckoo report if it's on disk, to verify the
    # ISO-timestamp / temporal-spread / lane-gutter fixes against a real file.
    cuckoo_path = Path(
        r"C:\Users\Omar\Desktop\action reoport\cc49d150e155326ec5c9063d5e206cb6"
        r"-d07fc68fd5e168f7d266f401ebdb7bf9dd36e882\cuckoo-analysis.json"
    )
    if cuckoo_path.exists():
        try:
            w._load_path(cuckoo_path, source_label="cuckoo report")
            _pump(app)
            w.on_nav("Graph")
            _pump(app)
            w.graph_view.fit_view()
            _pump(app)
            cuckoo_screenshot = out_dir / "ui_preview_graph_cuckoo.png"
            w.grab().save(str(cuckoo_screenshot), "PNG")
            print(f"Saved {cuckoo_screenshot}")
        except Exception as e:
            print(f"  (couldn't render Cuckoo file: {e})")
        # Reload the demo so the rest of the screenshots still make sense.
        w.on_load_demo()
        _pump(app)

    w.on_nav("About")
    _pump(app)
    about_path = out_dir / "ui_preview_about.png"
    w.grab().save(str(about_path), "PNG")
    print(f"Saved {about_path}")

    # Phase 7: AI Insights tab on the right panel
    w.on_nav("Dashboard")
    _pump(app)
    ai_index = next(
        (i for i in range(w.right_panel.tabs.count())
         if w.right_panel.tabs.tabText(i) == "AI Insights"),
        None,
    )
    if ai_index is not None:
        w.right_panel.tabs.setCurrentIndex(ai_index)
        _pump(app)
        ai_path = out_dir / "ui_preview_ai_insights.png"
        w.grab().save(str(ai_path), "PNG")
        print(f"Saved {ai_path}")

    # Phase 7: Export dialog
    from analystbridge.ui.export_dialog import ExportDialog
    dlg = ExportDialog(default_out_dir="exports", llm_engine=w._llm, parent=w)
    dlg.show()
    _pump(app)
    export_path = out_dir / "ui_preview_export_dialog.png"
    dlg.grab().save(str(export_path), "PNG")
    print(f"Saved {export_path}")
    dlg.close()

    # Phase 9+11: new full pages — MITRE / Indicators / YARA / Compare / Settings
    for nav, fname in (
        ("MITRE ATT&CK", "ui_preview_mitre.png"),
        ("Indicators", "ui_preview_indicators.png"),
        ("YARA", "ui_preview_yara.png"),
        ("Compare", "ui_preview_compare.png"),
        ("Settings", "ui_preview_settings.png"),
    ):
        w.on_nav(nav)
        _pump(app)
        w.grab().save(str(out_dir / fname), "PNG")
        print(f"Saved {out_dir / fname}")

    # Node Details preview — pick the powershell process node and screenshot.
    w.on_nav("Graph")
    _pump(app)
    if w._bundle is not None:
        powershell_id = next(
            (n for n in w._bundle.graph.nodes if "powershell" in str(n).lower()),
            next(iter(w._bundle.graph.nodes), None),
        )
        if powershell_id:
            w.on_node_clicked(powershell_id)
            _pump(app)
            w.grab().save(str(out_dir / "ui_preview_node_details.png"), "PNG")
            print(f"Saved {out_dir / 'ui_preview_node_details.png'}")

    w.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
