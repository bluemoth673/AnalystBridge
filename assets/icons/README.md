# Icons

AnalystBridge picks up PNG icons from this directory automatically. Two
folders are read:

```
assets/icons/        node icons (graph rectangles)
assets/icons/nav/    sidebar nav-bar icons
```

## Automatic colour inversion

**The loader recolours every icon to the theme's foreground colour by
default.** Drop in any black-on-transparent set (Heroicons, Tabler, Lucide…)
and they will render *white-on-dark* without any extra work.

Alpha is preserved so anti-aliased edges stay smooth.

## Node icons (graph)

Drop **24×24** (or 32×32) PNGs into `assets/icons/` using these filenames:

| Filename       | Used for                                       |
|----------------|------------------------------------------------|
| `process.png`  | Processes (explorer.exe, mshta.exe, …)         |
| `file.png`     | Files (payload.ps1, evil.dll, *.locked, …)    |
| `registry.png` | Windows registry keys (HKCU\…\Run, …)          |
| `network.png`  | Generic network nodes — used as fallback below |
| `domain.png`   | Domain names (cdn.badactor.com)                |
| `ip.png`       | IPv4 / IPv6 addresses                          |
| `url.png`      | URLs                                           |
| `module.png`   | Loaded modules / DLLs                          |
| `yara.png`     | YARA rule hits                                 |
| `api.png`      | API call events                                |
| `memory.png`   | Memory events (rwx regions, allocations)       |

## Sidebar nav icons

Drop **18×18** (or 24×24) PNGs into `assets/icons/nav/` using these filenames:

| Filename          | Sidebar item    |
|-------------------|-----------------|
| `dashboard.png`   | Dashboard       |
| `graph.png`       | Graph           |
| `process.png`     | Processes       |
| `network.png`     | Network         |
| `file.png`        | Files           |
| `registry.png`    | Registry        |
| `yara.png`        | YARA            |
| `mitre.png`       | MITRE ATT&CK    |
| `indicators.png`  | Indicators      |
| `compare.png`     | Compare         |
| `reports.png`     | Reports         |
| `settings.png`    | Settings        |
| `about.png`       | About           |

> Note: the loader falls back to the parent folder, so if you prefer to keep
> *one* icon set you can just put `process.png`, `network.png`, `file.png`,
> etc. in `assets/icons/` (no `nav/` subfolder needed) and the sidebar will
> reuse them.

## Recommended icon sets

* [Heroicons](https://heroicons.com/) — 24px outline, ships as black SVG.
  Use the SVG → PNG export at 24×24, drop here.
* [Tabler Icons](https://tabler.io/icons) — same vibe, more variety.
* [Lucide](https://lucide.dev/) — outline, MIT-licensed.

After dropping icons in, just relaunch AnalystBridge — the graph and sidebar
pick them up on the next startup.
