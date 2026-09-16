"""macOS-modern dark theme for opensleuth studio."""

COLORS = {
    "bg": "#0b0d12",
    "bg2": "#0e1118",
    "sidebar": "#0c0f15",
    "panel": "#141924",
    "panel2": "#1a2130",
    "hover": "#202839",
    "border": "rgba(255,255,255,9)",
    "borderSoft": "rgba(255,255,255,6)",
    "text": "#eaeef5",
    "muted": "#97a1b3",
    "faint": "#6b7484",
    "accent": "#5eead4",
    "accentText": "#0b2b25",
    "accent2": "#6aa8ff",
    "warn": "#ffc97d",
    "danger": "#ff8f9c",
    "ok": "#7ee2a8",
    "purple": "#c4a8ff",
}

FONT_STACK = '"SF Pro Display","Inter","Helvetica Neue","Segoe UI","Ubuntu",sans-serif'
MONO_STACK = '"SF Mono","JetBrains Mono","Cascadia Code","Ubuntu Mono",monospace'

A = COLORS["accent"]

QSS = f"""
* {{ font-family: {FONT_STACK}; font-size: 13px; }}
QMainWindow, QWidget {{ background: {COLORS['bg']}; color: {COLORS['text']}; }}
QLabel {{ background: transparent; color: {COLORS['text']}; }}
QLabel[muted="true"] {{ color: {COLORS['muted']}; }}
QLabel[h1="true"] {{ font-size: 25px; font-weight: 800; letter-spacing: -0.4px; }}
QLabel[h2="true"] {{ font-size: 16px; font-weight: 700; }}
QLabel[eyebrow="true"] {{ color: {COLORS['accent']}; font-size: 10.5px; font-weight: 800; letter-spacing: 2.2px; }}
QLabel[mono="true"] {{ font-family: {MONO_STACK}; font-size: 11px; color: {COLORS['muted']}; }}

/* hide all native checkbox indicators (custom widgets only) */
QCheckBox::indicator, QRadioButton::indicator {{ width: 0; height: 0; margin: 0; padding: 0; border: none; background: transparent; }}
QCheckBox, QRadioButton {{ background: transparent; spacing: 0; }}
QRadioButton {{ padding: 7px 14px; border-radius: 9px; color: {COLORS['muted']}; font-weight: 600; font-size: 12.5px; }}
QRadioButton:hover {{ background: rgba(255,255,255,4); color: {COLORS['text']}; }}
QRadioButton:checked {{ background: rgba(94,234,212,12); color: {A}; }}

/* sidebar */
#Sidebar {{ background: {COLORS['sidebar']}; border-right: 1px solid {COLORS['borderSoft']}; }}
#Logo {{ font-size: 17px; font-weight: 800; color: {COLORS['text']}; padding: 20px 22px 0 22px; letter-spacing: -0.2px; }}
#LogoDot {{ background: {A}; border-radius: 5px; }}
#LogoSub {{ color: {COLORS['faint']}; font-size: 10px; font-weight: 700; letter-spacing: 1.8px; padding: 3px 22px 18px 22px; }}
SidebarButton {{ text-align: left; padding: 10px 14px; margin: 1px 10px; border: none; border-radius: 10px;
  background: transparent; color: {COLORS['muted']}; font-size: 13px; font-weight: 600; }}
SidebarButton:hover {{ background: rgba(255,255,255,4); color: {COLORS['text']}; }}
SidebarButton:checked {{ background: rgba(94,234,212,11); color: {A}; }}

/* cards */
QFrame[card="true"] {{ background: rgba(255,255,255,3.2); border: 1px solid {COLORS['border']}; border-radius: 14px; }}
QFrame[cardHover="true"]:hover {{ background: rgba(255,255,255,5); border: 1px solid rgba(94,234,212,30); }}
QFrame[elevated="true"] {{ background: {COLORS['panel']}; border: 1px solid {COLORS['border']}; border-radius: 16px; }}

/* inputs */
QLineEdit, QPlainTextEdit, QComboBox {{
  background: rgba(255,255,255,3.5); border: 1px solid {COLORS['border']}; border-radius: 10px;
  padding: 9px 12px; color: {COLORS['text']}; selection-background-color: {COLORS['accent2']}; selection-color: #fff; }}
QLineEdit:hover, QPlainTextEdit:hover {{ border: 1px solid rgba(255,255,255,14); }}
QLineEdit:focus, QPlainTextEdit:focus {{ border: 1px solid rgba(94,234,212,55); background: rgba(255,255,255,5); }}
QLineEdit[mono="true"] {{ font-family: {MONO_STACK}; font-size: 11.5px; }}
QComboBox QAbstractItemView {{ background: {COLORS['panel2']}; border: 1px solid {COLORS['border']}; border-radius: 10px; padding: 4px; }}
QComboBox QAbstractItemView::item {{ padding: 6px 10px; border-radius: 6px; min-height: 22px; }}
QComboBox QAbstractItemView::item:selected {{ background: rgba(94,234,212,14); color: {COLORS['text']}; }}

/* buttons */
QPushButton {{
  background: rgba(255,255,255,5); border: 1px solid {COLORS['border']}; border-radius: 10px;
  padding: 9px 16px; color: {COLORS['text']}; font-weight: 600; }}
QPushButton:hover {{ background: rgba(255,255,255,8); border: 1px solid rgba(255,255,255,16); }}
QPushButton:pressed {{ background: rgba(255,255,255,11); }}
QPushButton:disabled {{ color: {COLORS['faint']}; background: rgba(255,255,255,3); border: 1px solid {COLORS['borderSoft']}; }}
QPushButton[primary="true"] {{ background: {A}; color: {COLORS['accentText']}; border: none; font-weight: 700; }}
QPushButton[primary="true"]:hover {{ background: #7ff0dc; }}
QPushButton[primary="true"]:pressed {{ background: #4ecfba; }}
QPushButton[primary="true"]:disabled {{ background: rgba(255,255,255,6); color: {COLORS['faint']}; }}
QPushButton[danger="true"] {{ background: {COLORS['danger']}; color: #33060c; border: none; font-weight: 700; }}

/* scrollbars */
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 9px; margin: 6px 2px 6px 0; }}
QScrollBar::handle:vertical {{ background: rgba(255,255,255,13); border-radius: 4px; min-height: 36px; }}
QScrollBar::handle:vertical:hover {{ background: rgba(255,255,255,22); }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 9px; margin: 0 6px 2px 6px; }}
QScrollBar::handle:horizontal {{ background: rgba(255,255,255,13); border-radius: 4px; min-width: 36px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* tables */
QTableWidget {{
  background: rgba(255,255,255,2.5); border: 1px solid {COLORS['border']}; border-radius: 14px;
  gridline-color: rgba(255,255,255,4); selection-background-color: rgba(106,168,255,25);
  selection-color: {COLORS['text']}; alternate-background-color: rgba(255,255,255,2); }}
QTableWidget::item {{ padding: 5px 8px; border: none; }}
QHeaderView::section {{
  background: transparent; border: none; border-bottom: 1px solid {COLORS['border']};
  padding: 9px 8px; color: {COLORS['muted']}; font-weight: 700; font-size: 11.5px; }}
QTableCornerButton::section {{ background: transparent; border: none; }}

/* tabs */
QTabWidget::pane {{ border: none; top: -1px; }}
QTabBar::tab {{
  background: transparent; padding: 8px 16px; margin-right: 4px; border-radius: 9px;
  color: {COLORS['muted']}; font-weight: 600; font-size: 12.5px; }}
QTabBar::tab:hover {{ background: rgba(255,255,255,5); color: {COLORS['text']}; }}
QTabBar::tab:selected {{ background: rgba(94,234,212,12); color: {A}; }}

/* progress */
QProgressBar {{ background: rgba(255,255,255,6); border: none; border-radius: 5px; height: 7px; text-align: center; }}
QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {COLORS['accent2']}, stop:1 {A}); border-radius: 5px; }}

/* log */
QTextEdit[log="true"] {{
  background: #080a0e; border: 1px solid {COLORS['border']}; border-radius: 14px;
  font-family: {MONO_STACK}; font-size: 11.5px; color: #9fe8c9; padding: 10px; selection-background-color: rgba(94,234,212,30); }}

QToolTip {{ background: {COLORS['panel2']}; color: {COLORS['text']}; border: 1px solid {COLORS['border']}; padding: 6px 9px; border-radius: 8px; }}

QStatusBar {{ background: {COLORS['bg2']}; }}
"""
