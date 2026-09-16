"""Studio screens: case builder, device, acquisition, results."""

import json
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..matrix import CHIP_RANK, USBLITER8_CHIPS, recommend
from .theme import COLORS
from .widgets import AnimatedStack, AppRow, DeviceCard, OptionCard, StatusPill
from .workers import AcquireWorker, AppListWorker, DeviceWorker, DumpWorker


def _lbl(text, muted=False, mono=False, h=None):
    l = QLabel(text)
    if muted:
        l.setProperty("muted", True)
    if mono:
        l.setProperty("mono", True)
    if h:
        l.setProperty(h, True)
    return l


def card():
    f = QFrame()
    f.setProperty("elevated", True)
    return f


def header(eyebrow, title, sub=None):
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 0)
    v.setSpacing(3)
    eb = QLabel(eyebrow.upper())
    eb.setProperty("eyebrow", True)
    v.addWidget(eb)
    v.addWidget(_lbl(title, h="h1"))
    if sub:
        v.addWidget(_lbl(sub, muted=True))
    return w


class CaseScreen(QWidget):
    case_saved = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(36, 30, 36, 30)
        lay.setSpacing(14)
        lay.addWidget(header("Evidence intake", "Case Builder",
                         "Document the examination. Consent and integrity metadata become part of the case file."))

        c = card()
        grid = QGridLayout(c)
        grid.setContentsMargins(20, 18, 20, 18)
        grid.setSpacing(12)
        self.fields = {}
        now = datetime.now()
        defaults = [
            ("case_id", "Case ID", f"CASE-{now:%Y%m%d-%H%M%S}", False),
            ("examiner", "Examiner", "", True),
            ("agency", "Agency / Unit", "", False),
            ("location", "Location", "", False),
            ("owner", "Device owner / subject", "", False),
        ]
        for i, (key, label, val, req) in enumerate(defaults):
            grid.addWidget(_lbl(label + (" *" if req else ""), muted=True), i, 0)
            e = QLineEdit(val)
            if key == "case_id":
                e.setReadOnly(True)
                e.setProperty("mono", True)
            self.fields[key] = e
            grid.addWidget(e, i, 1)
        grid.addWidget(_lbl("Date / time", muted=True), 0, 2)
        dt = QLineEdit(now.strftime("%Y-%m-%d %H:%M:%S"))
        dt.setReadOnly(True)
        grid.addWidget(dt, 0, 3)
        grid.addWidget(_lbl("Evidence destination", muted=True), 1, 2)
        row = QHBoxLayout()
        self.dest = QLineEdit(str(Path.home() / "cases" / defaults[0][2].replace(" ", "_")))
        b = QPushButton("Browse…")
        b.clicked.connect(self._browse)
        row.addWidget(self.dest, 1)
        row.addWidget(b)
        grid.addLayout(row, 1, 3)
        grid.addWidget(_lbl("Case notes", muted=True), 5, 0)
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Warrant / consent reference, chain of custody notes, scope…")
        self.notes.setMaximumHeight(110)
        grid.addWidget(self.notes, 5, 1, 1, 3)
        lay.addWidget(c)

        c2 = card()
        h = QHBoxLayout(c2)
        h.setContentsMargins(20, 14, 20, 14)
        col = QVBoxLayout()
        t = _lbl("Consent & legal authority")
        f = t.font(); f.setBold(True); t.setFont(f)
        col.addWidget(t)
        col.addWidget(_lbl("Confirm you are authorized to acquire this device (owner consent, warrant, or lawful seizure).", muted=True))
        h.addLayout(col, 1)
        self.consent = OptionCard("consent", "Authorized", "Consent / warrant confirmed", False)
        self.consent.toggle.toggled.connect(lambda c: None)
        h.addWidget(self.consent)
        lay.addWidget(c2)

        c3 = card()
        h3 = QHBoxLayout(c3)
        h3.setContentsMargins(20, 14, 20, 14)
        col3 = QVBoxLayout()
        t3 = _lbl("Evidence integrity")
        f3 = t3.font(); f3.setBold(True); t3.setFont(f3)
        col3.addWidget(t3)
        col3.addWidget(_lbl("SHA-256 manifest of every acquired artifact (recommended for court).", muted=True))
        h3.addLayout(col3, 1)
        self.hashing = OptionCard("hashing", "SHA-256 hashing", "Generate manifest.json with per-file hashes", True)
        h3.addWidget(self.hashing)
        lay.addWidget(c3)

        row = QHBoxLayout()
        row.addStretch(1)
        save = QPushButton("Save case")
        save.clicked.connect(self._save)
        nxt = QPushButton("Save & continue →")
        nxt.setProperty("primary", True)
        nxt.clicked.connect(self._save_continue)
        row.addWidget(save)
        row.addWidget(nxt)
        lay.addLayout(row)
        lay.addStretch(1)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Evidence destination", str(Path.home()))
        if d:
            self.dest.setText(d + "/" + self.fields["case_id"].text())

    def _collect(self):
        return {
            "case_id": self.fields["case_id"].text(),
            "examiner": self.fields["examiner"].text(),
            "agency": self.fields["agency"].text(),
            "location": self.fields["location"].text(),
            "owner": self.fields["owner"].text(),
            "created": datetime.now().isoformat(timespec="seconds"),
            "notes": self.notes.toPlainText(),
            "destination": self.dest.text(),
            "consent": self.consent.toggle.isChecked(),
            "sha256_manifest": self.hashing.toggle.isChecked(),
        }

    def _save(self):
        case = self._collect()
        if not case["examiner"].strip():
            self.fields["examiner"].setStyleSheet("border:1px solid #ff5f6d;")
            return None
        dest = Path(case["destination"])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "case.json").write_text(json.dumps(case, indent=2))
        self.case_saved.emit(case)
        return case

    def _save_continue(self):
        if self._save():
            self.window().nav_to(1)


class DeviceScreen(QWidget):
    device_ready = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._device = None
        self.card = None
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(40, 30, 40, 30)
        self.lay.setSpacing(14)
        self.lay.addWidget(header("Target", "Device Detection",
                                   "Connect an iPhone via USB. State and capabilities are probed live."))
        self.status = _lbl("Waiting for a device…", muted=True)
        self.lay.addWidget(self.status)
        self.card_area = QVBoxLayout()
        self.lay.addLayout(self.card_area)
        self.cap_area = QVBoxLayout()
        self.lay.addLayout(self.cap_area)
        self.lay.addStretch(1)
        self._worker = None
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll)
        self.timer.start(2500)
        self._poll()

    def showEvent(self, e):
        self.timer.start(2500)
        super().showEvent(e)

    def hideEvent(self, e):
        self.timer.stop()
        super().hideEvent(e)

    def _poll(self):
        if self._worker and self._worker.isRunning():
            return
        self._worker = DeviceWorker()
        self._worker.device_found.connect(self._found)
        self._worker.lost.connect(self._lost)
        self._worker.start()

    def _clear(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item is None:
                continue
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self._clear(item.layout())

    def _lost(self):
        if self._device is not None:
            self._device = None
            self.card = None
            self._clear(self.card_area)
            self._clear(self.cap_area)
            self.status.setText("Device disconnected.")

    def _found(self, dev):
        first = self._device is None
        changed = (not first and (self._device.get("udid") != dev.get("udid")
                                   or self._device.get("state") != dev.get("state")))
        self._device = dev
        if first or changed:
            self._render()
        elif self.card:
            self.card.update(dev["model"], f"{dev['ios']} ({dev['build']})",
                             dev["udid"], dev["state"], dev["chip"])

    def _render(self):
        d = self._device
        self._clear(self.card_area)
        self._clear(self.cap_area)
        self.status.setText("Device detected — live")
        self.card = DeviceCard(d["model"], f"{d['ios']} ({d['build']})", d["udid"], d["state"], d["chip"])
        self._fade_in(self.card)
        self.card_area.addWidget(self.card)

        rc = card()
        rl = QHBoxLayout(rc)
        rl.setContentsMargins(16, 10, 16, 10)
        rl.setSpacing(10)
        rl.addWidget(_lbl("State", muted=True))
        self.r_afu = QRadioButton("AFU — after first unlock")
        self.r_bfu = QRadioButton("BFU — before first unlock")
        (self.r_afu if d["state"] == "AFU" else self.r_bfu).setChecked(True)
        self.r_afu.toggled.connect(lambda _: self._render_caps())
        seg = QHBoxLayout()
        seg.setSpacing(6)
        seg.addWidget(self.r_afu)
        seg.addWidget(self.r_bfu)
        rl.addLayout(seg)
        rl.addStretch(1)
        rl.addWidget(_lbl(f"auto-detected: {d['state']}", muted=True))
        self.card_area.addWidget(rc)

        self._render_caps()

        wrap = QWidget()
        wr = QHBoxLayout(wrap)
        wr.setContentsMargins(0, 10, 0, 0)
        btn = QPushButton("Continue →")
        btn.setProperty("primary", True)
        btn.setMinimumWidth(150)
        btn.clicked.connect(self._go)
        wr.addStretch(1)
        wr.addWidget(btn)
        self.card_area.addWidget(wrap)

    def _fade_in(self, w):
        eff = QGraphicsOpacityEffect(w)
        w.setGraphicsEffect(eff)
        a = QPropertyAnimation(eff, b"opacity", w)
        a.setDuration(380)
        a.setStartValue(0.0)
        a.setEndValue(1.0)
        a.setEasingCurve(QEasingCurve.Type.OutCubic)
        a.start()
        self._fade = a

    def _chosen_state(self):
        return "AFU" if self.r_afu.isChecked() else "BFU"

    def _render_caps(self):
        self._clear(self.cap_area)
        d = self._device
        if not d:
            return
        state = self._chosen_state()
        c = card()
        v = QVBoxLayout(c)
        v.setContentsMargins(20, 16, 20, 8)
        v.setSpacing(0)
        v.addWidget(_lbl(f"Extraction routes · {d['chip']} · iOS {d['ios']} · {state}", h="h2"))
        v.addSpacing(10)
        rank = CHIP_RANK.get(d["chip"], 99)
        steps = recommend(d["chip"], d["ios"])
        for i, step in enumerate(steps):
            if step.startswith("logical"):
                pill = StatusPill("Available", "ok") if state == "AFU" else StatusPill("Locked", "warn")
            elif step.startswith("checkm8"):
                pill = StatusPill("Available", "ok") if rank <= 11 else StatusPill("Not possible", "danger")
            elif step.startswith("usbliter8"):
                pill = StatusPill("Available", "ok") if state in ("AFU", "BFU") else StatusPill("Locked", "warn")
            elif step.startswith(("jailbreak", "side-load")):
                pill = StatusPill("Available", "ok") if state == "AFU" else StatusPill("Locked", "warn")
            else:
                pill = StatusPill("Not possible", "danger")
            roww = QWidget()
            row = QHBoxLayout(roww)
            row.setContentsMargins(0, 9, 0, 9)
            row.setSpacing(12)
            row.addWidget(pill)
            txt = _lbl(step)
            txt.setWordWrap(True)
            row.addWidget(txt, 1)
            v.addWidget(roww)
            if i < len(steps) - 1:
                line = QFrame()
                line.setFixedHeight(1)
                line.setStyleSheet("background:rgba(255,255,255,5); border:none;")
                v.addWidget(line)
        self.cap_area.addWidget(c)

    def _go(self):
        d = dict(self._device)
        d["state"] = self._chosen_state()
        self.device_ready.emit(d)


class AcquireScreen(QWidget):
    acquisition_done = pyqtSignal(dict)
    want_report = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.device = None
        self.apps = []
        self.rows = {}
        self.stack = AnimatedStack()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.stack)

        # ---------------- page 1: configuration
        p1 = QWidget()
        self.lay = QVBoxLayout(p1)
        self.lay.setContentsMargins(36, 30, 36, 30)
        self.lay.setSpacing(14)
        self.banner = _lbl("Connect and configure a device first (Device page).", muted=True)
        self.lay.addWidget(self.banner)

        self.opt_area = QGridLayout()
        self.opt_area.setSpacing(12)
        self.lay.addLayout(self.opt_area)
        self.password = QLineEdit()
        self.password.setPlaceholderText("Backup password (enables encrypted backup + keychain)")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.lay.addWidget(self.password)

        apph = QHBoxLayout()
        apph.addWidget(_lbl("Applications", h="h2"))
        apph.addStretch(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search apps…")
        self.search.setMaximumWidth(220)
        self.search.textChanged.connect(self._filter_apps)
        apph.addWidget(self.search)
        allb = QPushButton("Select all")
        allb.clicked.connect(lambda: self._set_all(True))
        noneb = QPushButton("Select none")
        noneb.clicked.connect(lambda: self._set_all(False))
        apph.addWidget(allb)
        apph.addWidget(noneb)
        self.lay.addLayout(apph)
        self.app_count = _lbl("", muted=True)
        self.lay.addWidget(self.app_count)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.app_container = QWidget()
        self.app_lay = QVBoxLayout(self.app_container)
        self.app_lay.setSpacing(8)
        self.app_lay.addStretch(1)
        self.scroll.setWidget(self.app_container)
        self.scroll.setMinimumHeight(280)
        self.lay.addWidget(self.scroll, 1)

        row = QHBoxLayout()
        row.addStretch(1)
        self.acquire_btn = QPushButton("▶  Start acquisition")
        self.acquire_btn.setProperty("primary", True)
        self.acquire_btn.clicked.connect(self._start)
        row.addWidget(self.acquire_btn)
        self.lay.addLayout(row)
        self.stack.addWidget(p1)

        # ---------------- page 2: progress
        p2 = QWidget()
        pl = QVBoxLayout(p2)
        pl.setContentsMargins(36, 30, 36, 30)
        pl.setSpacing(14)
        pl.addWidget(header("Running", "Acquisition in progress"))
        self.prog = QProgressBar()
        self.prog.setValue(0)
        pl.addWidget(self.prog)
        self.steps_area = QVBoxLayout()
        pl.addLayout(self.steps_area)
        self.logw = QTextEdit()
        self.logw.setProperty("log", True)
        self.logw.setReadOnly(True)
        pl.addWidget(self.logw, 1)
        br = QHBoxLayout()
        self.report_btn = QPushButton("Generate artifact report")
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self._run_dump)
        self.done_lbl = _lbl("", muted=True)
        br.addWidget(self.done_lbl)
        br.addStretch(1)
        br.addWidget(self.report_btn)
        pl.addLayout(br)
        self.stack.addWidget(p2)

    def load_device(self, device, case=None):
        self.device = device
        self.case = case
        afu = device["state"] == "AFU"
        rank = CHIP_RANK.get(device["chip"], 99)
        self.banner.setText(
            f"{device['model']} · iOS {device['ios']} · {device['state']} detected"
            + (" — full acquisition enabled." if afu else " — BFU: routes limited.")
            + ("" if case else "  ·  Save a case to enable acquisition.")
        )
        self.acquire_btn.setEnabled(case is not None and afu)
        self._clear_opts()
        opts = [
            ("backup", "Full device backup", "App sandboxes, messages, contacts, calls, Safari, media metadata", afu),
            ("encrypted", "Encrypted backup + keychain", "Adds keychain (passwords, tokens, WiFi) — requires backup password", afu),
            ("media", "Media via AFC", "DCIM, Downloads, Recordings, Books, Podcasts", afu),
            ("crash", "Crash reports", "All .ips logs + analytics", afu),
            ("diag", "Diagnostics + device info", "MobileGestalt, IORegistry, battery, WiFi, processes, wallpaper", afu),
            ("syslog", "Syslog capture", "30-second live system log window", afu),
            ("apps", "Selected app containers", "App sandboxes for toggled apps below", afu),
        ]
        self.options = {o[0]: o[3] for o in opts}
        for i, (key, title, desc, en) in enumerate(opts):
            oc = OptionCard(key, title, desc, checked=en, enabled=en)
            oc.toggled.connect(self._opt_toggled)
            self.opt_area.addWidget(oc, i // 2, i % 2)
        if not afu and rank <= 11:
            oc = OptionCard("checkm8", "checkm8 BFU flow", "A7-A11 bootrom exploit (run from terminal: acquire bfu --chip)", True)
            self.opt_area.addWidget(oc, 4, 0)
        if not afu and d["chip"] in USBLITER8_CHIPS:
            oc = OptionCard("usbliter8", "usbliter8 BFU flow", "A12/A13 bootrom via RP2350 rig (run: acquire usbliter8)", True)
            self.opt_area.addWidget(oc, 4, 1)
        self._load_apps()

    def _clear_opts(self):
        while self.opt_area.count():
            item = self.opt_area.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _opt_toggled(self, key, checked):
        self.options[key] = checked

    def _load_apps(self):
        while self.app_lay.count() > 1:
            item = self.app_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.rows = {}
        self.apps = []
        if not self.device or self.device["state"] != "AFU":
            self.app_count.setText("App enumeration requires AFU state.")
            return
        self.app_count.setText("Enumerating apps…")
        self.app_worker = AppListWorker(Path.home() / ".cache" / "opensleuth-icons")
        self.app_worker.app_found.connect(self._app_found)
        self.app_worker.done.connect(lambda n: self.app_count.setText(f"{n} apps — toggle to include in extraction"))
        self.app_worker.start()

    def _app_found(self, a):
        self.apps.append(a)
        row = AppRow(a["name"], a["bundle"], a["version"], a.get("icon"))
        row.set_checked(True)
        self.rows[a["bundle"]] = row
        self.app_lay.insertWidget(self.app_lay.count() - 1, row)

    def _set_all(self, checked):
        for r in self.rows.values():
            r.set_checked(checked)

    def _filter_apps(self, text):
        t = text.lower()
        for bundle, row in self.rows.items():
            row.setVisible(t in bundle.lower() or t in row.findChildren(QLabel)[1].text().lower())

    def _start(self):
        if not self.device or not self.case:
            return
        dest = Path(self.case["destination"])
        sel = [b for b, r in self.rows.items() if r.toggle.isChecked()] if self.options.get("apps") else []
        self._clear_steps()
        self.stack.slide_to(1)
        self.worker = AcquireWorker(dest, self.device, self.options, sel, self.password.text())
        self.worker.step_start.connect(self._step_start)
        self.worker.step_done.connect(self._step_done)
        self.worker.log.connect(lambda s: self.logw.append(s))
        self.worker.progress.connect(self.prog.setValue)
        self.worker.finished_all.connect(self._finished)
        self.worker.start()

    def _clear_steps(self):
        while self.steps_area.count():
            item = self.steps_area.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.step_labels = {}
        self.logw.clear()

    def _step_start(self, name):
        row = QHBoxLayout()
        lbl = _lbl(name)
        row.addWidget(lbl)
        row.addStretch(1)
        pill = StatusPill("RUNNING", "info")
        row.addWidget(pill)
        w = QWidget(); w.setLayout(row)
        self.steps_area.addWidget(w)
        self.step_labels[name] = (lbl, pill, w)

    def _step_done(self, name, ok, note):
        lbl, pill, w = self.step_labels.get(name, (None, None, None))
        if pill:
            pill.set_state("Done" if ok else "Failed", "ok" if ok else "danger")
            lbl.setText(f"{name} — {note}")

    def _finished(self, ok):
        self.prog.setValue(100)
        self.done_lbl.setText("Acquisition complete." if ok else "Acquisition finished with failures — see log.")
        self.report_btn.setEnabled(True)
        self.acquisition_done.emit({"dest": self.case["destination"], "ok": ok})

    def _run_dump(self):
        self.report_btn.setEnabled(False)
        self.done_lbl.setText("Parsing backup into artifact report…")
        self.dump_worker = DumpWorker(Path(self.case["destination"]), self.device["udid"])
        self.dump_worker.done.connect(self._dump_done)
        self.dump_worker.start()

    def _dump_done(self, counts):
        self.window().ctx["results"] = counts
        self.want_report.emit()

    def _filter_label(self):
        pass


class ResultsScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(36, 30, 36, 30)
        self.lay.setSpacing(14)
        self.lay.addWidget(header("Findings", "Examination Results"))
        self.cards = QGridLayout()
        self.cards.setSpacing(12)
        self.lay.addLayout(self.cards)
        row = QHBoxLayout()
        self.open_report = QPushButton("Open HTML report")
        self.open_report.clicked.connect(self._open_report)
        self.open_folder = QPushButton("Open evidence folder")
        self.open_folder.clicked.connect(self._open_folder)
        row.addWidget(self.open_report)
        row.addWidget(self.open_folder)
        row.addStretch(1)
        self.lay.addLayout(row)
        self.tabs = QTabWidget()
        self.lay.addWidget(self.tabs, 1)

    def load(self, ctx):
        counts = ctx.get("results", {})
        self._clear(self.cards)
        self.tabs.clear()
        names = [
            ("messages", "Messages"), ("contacts", "Contacts"), ("calls", "Calls"),
            ("history", "Web history"), ("bookmarks", "Bookmarks"),
            ("keychain", "Keychain"), ("voicemail", "Voicemail"), ("notes", "Notes"),
            ("app_databases", "App DBs"),
        ]
        for i, (k, label) in enumerate(names):
            c = card()
            v = QVBoxLayout(c)
            v.setContentsMargins(16, 12, 16, 12)
            n = _lbl(str(counts.get(k, 0)))
            f = n.font(); f.setPointSize(22); f.setBold(True); f.setFamily("monospace"); n.setFont(f)
            v.addWidget(n)
            v.addWidget(_lbl(label, muted=True))
            self.cards.addWidget(c, i // 5, i % 5)
        dest = Path(ctx["case"]["destination"])
        art = dest / "report" / "artifacts.json"
        if art.exists():
            try:
                data = json.loads(art.read_text())
                for k, label in names:
                    rows = data.get(k)
                    if isinstance(rows, list) and rows:
                        self._add_table(label, rows)
            except Exception:
                pass

    def _add_table(self, label, rows):
        cols = list(rows[0].keys())[:8]
        t = QTableWidget()
        t.setColumnCount(len(cols))
        t.setRowCount(min(len(rows), 500))
        t.setHorizontalHeaderLabels(cols)
        for r, row in enumerate(rows[:500]):
            for c, k in enumerate(cols):
                v = row.get(k)
                t.setItem(r, c, QTableWidgetItem("" if v is None else str(v)[:200]))
        t.resizeColumnsToContents()
        self.tabs.addTab(t, f"{label} ({len(rows)})")

    def _clear(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _open_report(self):
        import subprocess
        dest = self.window().ctx["case"]["destination"]
        subprocess.Popen(["xdg-open", str(Path(dest) / "report" / "report.html")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _open_folder(self):
        import subprocess
        dest = self.window().ctx["case"]["destination"]
        subprocess.Popen(["xdg-open", dest], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
