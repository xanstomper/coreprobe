"""Main window: sidebar navigation, page stack, status bar, shared context."""

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QVBoxLayout,
    QWidget,
)

from .screens import AcquireScreen, CaseScreen, DeviceScreen, ResultsScreen
from .theme import COLORS
from .widgets import AnimatedStack, SidebarButton


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ctx = {"case": None, "device": None, "results": None}
        self.setWindowTitle("opensleuth studio — mobile forensics")
        self.resize(1460, 920)
        self.setMinimumSize(1180, 760)

        root = QWidget()
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        # ---------------- sidebar
        sb = QFrame()
        sb.setObjectName("Sidebar")
        sb.setFixedWidth(236)
        v = QVBoxLayout(sb)
        v.setContentsMargins(0, 0, 0, 12)
        v.setSpacing(0)
        logo_row = QHBoxLayout()
        logo_row.setContentsMargins(22, 20, 22, 0)
        logo_row.setSpacing(9)
        dot = QLabel()
        dot.setObjectName("LogoDot")
        dot.setFixedSize(12, 12)
        logo = QLabel("opensleuth")
        logo.setObjectName("Logo")
        logo.setStyleSheet("padding:0;")
        logo_row.addWidget(dot)
        logo_row.addWidget(logo, 1)
        v.addLayout(logo_row)
        sub = QLabel("MOBILE FORENSICS STUDIO")
        sub.setObjectName("LogoSub")
        v.addWidget(sub)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons = []
        for i, (name, icon) in enumerate(
            [("Case Builder", "▤"), ("Target Device", "⌁"), ("Acquisition", "⇩"), ("Results", "◷")]
        ):
            b = SidebarButton(f"  {icon}   {name}")
            b.setFixedHeight(44)
            self.nav_group.addButton(b, i)
            v.addWidget(b)
            self.nav_buttons.append(b)
        self.nav_buttons[0].setChecked(True)
        self.nav_group.idClicked.connect(self.nav_to)

        v.addStretch(1)
        foot = QLabel("open-source · evidence-safe\nlogical + public exploit routes")
        foot.setObjectName("LogoSub")
        v.addWidget(foot)
        h.addWidget(sb)

        # ---------------- pages
        self.stack = AnimatedStack()
        self.case_screen = CaseScreen()
        self.device_screen = DeviceScreen()
        self.acquire_screen = AcquireScreen()
        self.results_screen = ResultsScreen()
        for p in (self.case_screen, self.device_screen, self.acquire_screen, self.results_screen):
            self.stack.addWidget(p)
        h.addWidget(self.stack, 1)

        # ---------------- wiring
        self.case_screen.case_saved.connect(self._case_saved)
        self.device_screen.device_ready.connect(self._device_ready)
        self.acquire_screen.acquisition_done.connect(self._acq_done)
        self.acquire_screen.want_report.connect(lambda: self.nav_to(3))

        self.statusBar().showMessage("Ready — create or load a case to begin.")
        self.statusBar().setStyleSheet(
            f"color:{COLORS['muted']}; background:{COLORS['bg2']}; border-top:1px solid {COLORS['border']};"
        )

    def nav_to(self, index):
        self.stack.slide_to(index)
        if 0 <= index < len(self.nav_buttons):
            self.nav_buttons[index].setChecked(True)
        if index == 3 and self.ctx.get("case"):
            self.results_screen.load(self.ctx)

    def _case_saved(self, case):
        self.ctx["case"] = case
        if self.ctx.get("device"):
            self.acquire_screen.load_device(self.ctx["device"], case)
        self.statusBar().showMessage(f"Case saved: {case['case_id']} → {case['destination']}")

    def _device_ready(self, dev):
        self.ctx["device"] = dev
        self.ctx["results"] = None
        self.acquire_screen.load_device(dev, self.ctx.get("case"))
        self.statusBar().showMessage(
            f"Device detected: {dev['model']} · iOS {dev['ios']} · {dev['state']} · {dev['chip']}"
            + ("" if self.ctx.get("case") else " — save a case to acquire")
        )
        if self.ctx.get("case"):
            self.nav_to(2)

    def _acq_done(self, info):
        self.statusBar().showMessage(
            "Acquisition complete." if info.get("ok") else "Acquisition finished with failures."
        )
