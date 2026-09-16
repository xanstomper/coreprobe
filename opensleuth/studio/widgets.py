"""Custom widgets: animated toggles, pills, app rows, device card, animated stack."""

import hashlib

from PyQt6.QtCore import QEasingCurve, QPropertyAnimation, Qt, pyqtProperty, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath, QPixmap
from PyQt6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .theme import COLORS


def rounded_pixmap(pix, size, radius=12):
    out = QPixmap(size, size)
    out.fill(Qt.GlobalColor.transparent)
    p = QPainter(out)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    path = QPainterPath()
    path.addRoundedRect(0, 0, size, size, radius, radius)
    p.setClipPath(path)
    scaled = pix.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                        Qt.TransformationMode.SmoothTransformation)
    p.drawPixmap(-(scaled.width() - size) // 2, -(scaled.height() - size) // 2, scaled)
    p.end()
    return out


def tile_pixmap(name, size=48):
    h = int(hashlib.md5(name.encode()).hexdigest(), 16)
    color = QColor.fromHsv(h % 360, 90, 110)
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(color)
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(0, 0, size, size, 12, 12)
    p.setPen(QColor("#f2f5f9"))
    f = QFont(); f.setBold(True); f.setPointSize(14)
    p.setFont(f)
    initials = "".join(w[0] for w in name.split()[:2]).upper() or name[:2].upper()
    p.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, initials)
    p.end()
    return pix


def soften(widget, opacity=0.55):
    eff = QGraphicsOpacityEffect(widget)
    eff.setOpacity(opacity)
    widget.setGraphicsEffect(eff)


class ToggleSwitch(QCheckBox):
    """Animated iOS-style toggle (44x24)."""

    toggledAnim = pyqtSignal(bool)

    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setChecked(checked)
        self._pos = 1.0 if checked else 0.0
        self.setFixedSize(44, 24)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def get_pos(self):
        return self._pos

    def set_pos(self, v):
        self._pos = v
        self.update()

    pos = pyqtProperty(float, get_pos, set_pos)

    def mouseReleaseEvent(self, e):
        if self.isEnabled() and self.rect().contains(e.position().toPoint()):
            self.setChecked(not self.isChecked())
            self._animate()
            self.toggledAnim.emit(self.isChecked())
        else:
            super().mouseReleaseEvent(e)

    def _animate(self):
        a = QPropertyAnimation(self, b"pos", self)
        a.setDuration(150)
        a.setEasingCurve(QEasingCurve.Type.OutCubic)
        a.setEndValue(1.0 if self.isChecked() else 0.0)
        a.start()
        self._anim = a

    def setEnabled(self, en):
        super().setEnabled(en)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.isEnabled():
            track = QColor(COLORS["accent"]) if self._pos > 0.5 else QColor(38, 45, 58)
        else:
            track = QColor(28, 33, 43)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(0, 0, 44, 24, 12, 12)
        knob_x = 3 + self._pos * (44 - 26)
        p.setBrush(QColor("#f5f8fc") if self.isEnabled() else QColor("#8a94a6"))
        p.drawEllipse(int(knob_x), 3, 18, 18)
        p.end()


class StatusPill(QLabel):
    """Soft pastel status pill."""

    MAP = {
        "ok": ("rgba(126,226,168,14)", COLORS["ok"]),
        "warn": ("rgba(255,201,125,14)", COLORS["warn"]),
        "danger": ("rgba(255,143,156,14)", COLORS["danger"]),
        "accent": ("rgba(94,234,212,14)", COLORS["accent"]),
        "info": ("rgba(106,168,255,14)", "#9cc0ff"),
        "muted": ("rgba(255,255,255,7)", COLORS["muted"]),
        "purple": ("rgba(196,168,255,14)", COLORS["purple"]),
    }

    def __init__(self, text, kind="muted"):
        super().__init__(text.upper())
        bg, fg = self.MAP.get(kind, self.MAP["muted"])
        border = bg.replace("14)", "38)")
        self.setStyleSheet(
            f"background:{bg}; color:{fg}; border:1px solid {border}; border-radius:11px;"
            f"padding:3px 11px; font-size:10px; font-weight:800; letter-spacing:0.8px;"
        )
        self.setFixedHeight(22)

    def set_state(self, text, kind):
        bg, fg = self.MAP.get(kind, self.MAP["muted"])
        border = bg.replace("14)", "38)")
        self.setText(text.upper())
        self.setStyleSheet(
            f"background:{bg}; color:{fg}; border:1px solid {border}; border-radius:11px;"
            f"padding:3px 11px; font-size:10px; font-weight:800; letter-spacing:0.8px;"
        )


class SidebarButton(QCheckBox):
    pass


class AnimatedStack(QStackedWidget):
    """Slide transition between pages."""

    def __init__(self):
        super().__init__()
        self._animating = False
        self._anims = []

    def slide_to(self, index):
        if index == self.currentIndex() or self._animating or index < 0 or index >= self.count():
            self.setCurrentIndex(index)
            return
        self._animating = True
        old_i = self.currentIndex()
        old = self.widget(old_i)
        new = self.widget(index)
        self.setCurrentIndex(index)
        w = self.width()
        direction = 1 if index > old_i else -1
        new.move(direction * w, 0)
        self._run(new, 0, False)
        self._run(old, -direction * w, True)

    def _run(self, widget, endx, hide):
        a = QPropertyAnimation(widget, b"pos", self)
        a.setDuration(260)
        a.setEasingCurve(QEasingCurve.Type.OutCubic)
        a.setStartValue(widget.pos())
        a.setEndValue(widget.pos() + widget.pos().__class__(endx - widget.pos().x(), 0))
        if hide:
            a.finished.connect(widget.hide)
        else:
            a.finished.connect(lambda: setattr(self, "_animating", False))
        a.start()
        self._anims.append(a)


class AppRow(QFrame):
    """One row: app icon + name + bundle + toggle."""

    toggled = pyqtSignal(str, bool)

    def __init__(self, name, bundle, version, icon_path=None):
        super().__init__()
        self.setProperty("cardHover", True)
        self.bundle = bundle
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 9, 14, 9)
        lay.setSpacing(13)
        icon = QLabel()
        if icon_path:
            pix = QPixmap(icon_path)
            icon.setPixmap(rounded_pixmap(pix, 46) if not pix.isNull() else tile_pixmap(name, 46))
        else:
            icon.setPixmap(tile_pixmap(name, 46))
        lay.addWidget(icon)
        col = QVBoxLayout()
        col.setSpacing(1)
        nm = QLabel(name)
        f = nm.font(); f.setBold(True); f.setPointSize(12); nm.setFont(f)
        col.addWidget(nm)
        sub = QLabel(f"{bundle}  ·  v{version}")
        sub.setProperty("muted", True)
        sub.setStyleSheet("font-size:10.5px;")
        col.addWidget(sub)
        lay.addLayout(col, 1)
        self.toggle = ToggleSwitch(True)
        self.toggle.toggledAnim.connect(lambda c: self.toggled.emit(self.bundle, c))
        lay.addWidget(self.toggle)

    def set_checked(self, c):
        self.toggle.setChecked(c)
        self.toggle._animate()


class OptionCard(QFrame):
    """Acquisition option card with title, description, toggle."""

    toggled = pyqtSignal(str, bool)

    def __init__(self, key, title, desc, checked=True, enabled=True, badge=None):
        super().__init__()
        self.key = key
        self.setProperty("cardHover", True)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(14)
        col = QVBoxLayout(); col.setSpacing(2)
        top = QHBoxLayout()
        t = QLabel(title)
        f = t.font(); f.setBold(True); f.setPointSizeF(12.5); t.setFont(f)
        top.addWidget(t)
        if badge:
            top.addWidget(StatusPill(badge, "purple"))
            top.addSpacing(4)
        col.addLayout(top)
        d = QLabel(desc)
        d.setProperty("muted", True)
        d.setWordWrap(True)
        d.setStyleSheet("font-size:11.5px;")
        col.addWidget(d)
        lay.addLayout(col, 1)
        self.toggle = ToggleSwitch(checked)
        self.toggle.setEnabled(enabled)
        self.toggle.toggledAnim.connect(lambda c: self.toggled.emit(self.key, c))
        lay.addWidget(self.toggle)
        if not enabled:
            soften(self, 0.5)


class DeviceCard(QFrame):
    def __init__(self, model, ios, udid, state, chip):
        super().__init__()
        self.setProperty("elevated", True)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 18, 0)
        lay.setSpacing(0)
        bar = QFrame()
        bar.setFixedWidth(4)
        bar.setStyleSheet(f"background:{COLORS['accent']}; border-radius:2px;")
        lay.addWidget(bar)
        inner = QVBoxLayout()
        inner.setContentsMargins(18, 15, 0, 15)
        inner.setSpacing(5)
        top = QHBoxLayout()
        self._name_lbl = QLabel(model)
        f = self._name_lbl.font(); f.setPointSize(17); f.setBold(True); self._name_lbl.setFont(f)
        top.addWidget(self._name_lbl)
        top.addStretch(1)
        self._state_pill = StatusPill(state, "ok" if state == "AFU" else "warn")
        top.addWidget(self._state_pill)
        top.addSpacing(6)
        self._chip_pill = StatusPill(chip, "info")
        top.addWidget(self._chip_pill)
        inner.addLayout(top)
        self._meta = QLabel(f"iOS {ios}")
        self._meta.setProperty("muted", True)
        inner.addWidget(self._meta)
        self._ud = QLabel(udid)
        self._ud.setProperty("mono", True)
        self._ud.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        inner.addWidget(self._ud)
        lay.addLayout(inner, 1)

    def update(self, model, ios, udid, state, chip):
        self._name_lbl.setText(model)
        self._meta.setText(f"iOS {ios}")
        self._ud.setText(udid)
        self._state_pill.set_state(state, "ok" if state == "AFU" else "warn")
        self._chip_pill.set_state(chip, "info")
