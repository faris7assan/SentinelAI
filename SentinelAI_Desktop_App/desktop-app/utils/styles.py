DARK = """
* { font-family: 'Inter', 'Roboto', 'Segoe UI', sans-serif; font-size: 13px; }
QMainWindow, QDialog, QWidget#centralWidget { background: #0B0E14; color: #E2E8F0; }
QWidget { color: #E2E8F0; }
QTabWidget::pane { border: 1px solid #1C2331; background: #131822; border-radius: 8px; }
QTabBar::tab { background: #0B0E14; color: #64748B; padding: 12px 24px; border-radius: 6px 6px 0 0; margin-right: 4px; font-weight: 600; font-size: 12px; }
QTabBar::tab:selected { background: #131822; color: #00E5FF; border-bottom: 2px solid #00E5FF; }
QTabBar::tab:hover:!selected { color: #E2E8F0; background: #1C2331; }
QPushButton { background: #1C2331; color: #E2E8F0; border: 1px solid #2D3748; border-radius: 6px; padding: 8px 18px; font-weight: 600; font-size: 13px; }
QPushButton:hover { background: #2D3748; color: #00E5FF; border-color: #00E5FF; }
QPushButton:pressed { background: #0B0E14; color: #00B8D9; border-color: #00B8D9; }
QPushButton:disabled { color: #475569; background: #0F131C; border-color: #1C2331; }
QPushButton[objectName="primary"] { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0052D4, stop:0.5 #4364F7, stop:1 #6FB1FC); border: none; color: #ffffff; }
QPushButton[objectName="primary"]:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4364F7, stop:1 #6FB1FC); }
QPushButton[objectName="success"] { background: #059669; border-color: #059669; color: #ffffff; }
QPushButton[objectName="success"]:hover { background: #10B981; }
QPushButton[objectName="danger"] { background: #E11D48; border-color: #E11D48; color: #ffffff; }
QPushButton[objectName="danger"]:hover { background: #F43F5E; }
QPushButton[objectName="warning"] { background: #D97706; border-color: #D97706; color: #ffffff; }
QPushButton[objectName="warning"]:hover { background: #F59E0B; }
QLineEdit, QTextEdit, QPlainTextEdit { background: #0B0E14; color: #00E5FF; border: 1px solid #2D3748; border-radius: 6px; padding: 8px 12px; selection-background-color: #0052D4; font-size: 13px; }
QLineEdit:focus, QTextEdit:focus { border: 1px solid #00E5FF; background: #0F131C; }
QComboBox { background: #1C2331; color: #E2E8F0; border: 1px solid #2D3748; border-radius: 6px; padding: 8px 12px; min-width: 140px; }
QComboBox:hover { border-color: #00E5FF; }
QComboBox QAbstractItemView { background: #131822; color: #E2E8F0; selection-background-color: #2D3748; selection-color: #00E5FF; border: 1px solid #2D3748; outline: 0px; }
QComboBox::drop-down { border: none; width: 24px; }
QProgressBar { background: #0F131C; border: 1px solid #2D3748; border-radius: 8px; text-align: center; color: #F8FAFC; height: 16px; font-weight: bold; font-size: 11px; }
QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00E5FF, stop:1 #0052D4); border-radius: 7px; }
QTableWidget, QTableView { background: #131822; color: #E2E8F0; border: 1px solid #1C2331; border-radius: 8px; gridline-color: #1C2331; alternate-background-color: #0B0E14; selection-background-color: #1E293B; outline: none; }
QTableWidget::item, QTableView::item { padding: 6px 10px; border-bottom: 1px solid #1C2331; }
QTableWidget::item:selected, QTableView::item:selected { background: #1E293B; color: #00E5FF; }
QHeaderView::section { background: #0F131C; color: #94A3B8; border: none; border-bottom: 1px solid #1C2331; padding: 10px 12px; font-weight: 700; font-size: 11px; letter-spacing: 0.8px; text-transform: uppercase; }
QScrollBar:vertical { background: #0B0E14; width: 10px; margin: 0px; border-radius: 5px; }
QScrollBar::handle:vertical { background: #2D3748; border-radius: 5px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #4A5568; }
QScrollBar:horizontal { background: #0B0E14; height: 10px; margin: 0px; border-radius: 5px; }
QScrollBar::handle:horizontal { background: #2D3748; border-radius: 5px; min-width: 24px; }
QGroupBox { border: 1px solid #1C2331; border-radius: 10px; margin-top: 14px; padding-top: 18px; color: #94A3B8; font-weight: 700; background: #131822; }
QGroupBox::title { subcontrol-origin: margin; left: 16px; padding: 0 8px; color: #00E5FF; font-size: 12px; letter-spacing: 0.5px; }
QStatusBar { background: #0B0E14; color: #64748B; border-top: 1px solid #1C2331; padding: 4px; font-size: 11px; }
QLabel[objectName="sub"] { color: #64748B; font-size: 12px; font-weight: 500; }
QLabel[objectName="ok"] { color: #10B981; font-weight: 700; }
QLabel[objectName="err"] { color: #EF4444; font-weight: 700; }
QLabel[objectName="warn"] { color: #F59E0B; font-weight: 700; }
QSplitter::handle { background: #1C2331; width: 4px; border-radius: 2px; }
QCheckBox { spacing: 8px; color: #E2E8F0; font-weight: 500; }
QCheckBox::indicator { width: 18px; height: 18px; border-radius: 4px; border: 1px solid #2D3748; background: #0B0E14; }
QCheckBox::indicator:checked { background: #00E5FF; border-color: #00E5FF; image: url(data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="%230B0E14" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>); }
QToolTip { background: #131822; color: #00E5FF; border: 1px solid #2D3748; border-radius: 4px; padding: 6px 10px; font-weight: bold; font-size: 12px; }
QSpinBox { background: #1C2331; color: #E2E8F0; border: 1px solid #2D3748; border-radius: 6px; padding: 8px; }
QSpinBox:focus { border-color: #00E5FF; background: #131822; }
"""

LIGHT = """
* { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; }
QMainWindow,QWidget,QDialog { background:#F1F5F9; color:#0F172A; }
QTabWidget::pane { border:1px solid #CBD5E1; background:#FFFFFF; border-radius:6px; }
QTabBar::tab { background:#E2E8F0; color:#475569; padding:9px 18px; border-radius:4px 4px 0 0; margin-right:2px; min-width:90px; }
QTabBar::tab:selected { background:#FFFFFF; color:#2563EB; border-bottom:2px solid #2563EB; font-weight:bold; }
QTabBar::tab:hover { color:#0F172A; background:#CBD5E1; }
QPushButton { background:#FFFFFF; color:#0F172A; border:1px solid #CBD5E1; border-radius:6px; padding:7px 16px; font-weight:600; }
QPushButton:hover { background:#F1F5F9; color:#2563EB; border-color:#2563EB; }
QPushButton[objectName="primary"] { background:#2563EB; border-color:#2563EB; color:#ffffff; }
QPushButton[objectName="primary"]:hover { background:#3B82F6; }
QPushButton[objectName="success"] { background:#059669; border-color:#059669; color:#ffffff; }
QPushButton[objectName="danger"]  { background:#DC2626; border-color:#DC2626; color:#ffffff; }
QPushButton[objectName="warning"] { background:#D97706; border-color:#D97706; color:#ffffff; }
QLineEdit,QTextEdit,QPlainTextEdit { background:#FFFFFF; color:#0F172A; border:1px solid #CBD5E1; border-radius:6px; padding:6px 10px; font-weight:500; }
QLineEdit:focus,QTextEdit:focus { border-color:#2563EB; }
QComboBox { background:#FFFFFF; color:#0F172A; border:1px solid #CBD5E1; border-radius:6px; padding:6px 10px; }
QComboBox QAbstractItemView { background:#FFFFFF; selection-background-color:#2563EB; selection-color:#ffffff; }
QProgressBar { background:#E2E8F0; border:1px solid #CBD5E1; border-radius:6px; text-align:center; height:22px; font-weight:bold; }
QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #2563EB,stop:1 #3B82F6); border-radius:5px; }
QTableWidget,QTableView { background:#FFFFFF; color:#0F172A; border:1px solid #CBD5E1; border-radius:6px; alternate-background-color:#F8FAFC; gridline-color:#E2E8F0; }
QTableWidget::item:selected,QTableView::item:selected { background:#2563EB; color:#ffffff; }
QHeaderView::section { background:#F1F5F9; color:#475569; border:none; padding:8px 10px; font-weight:700; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
QScrollBar:vertical { background:#F1F5F9; width:8px; }
QScrollBar::handle:vertical { background:#CBD5E1; border-radius:4px; }
QGroupBox { border:1px solid #CBD5E1; border-radius:8px; margin-top:10px; padding-top:14px; color:#475569; font-weight:700; }
QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 5px; color:#2563EB; }
QStatusBar { background:#E2E8F0; color:#475569; border-top:1px solid #CBD5E1; padding:3px; }
QLabel[objectName="sub"] { color:#475569; font-size:12px; }
QCheckBox::indicator { width:16px; height:16px; border-radius:3px; border:1px solid #CBD5E1; background:#FFFFFF; }
QCheckBox::indicator:checked { background:#2563EB; border-color:#2563EB; }
"""
