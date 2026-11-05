"""Kit do Hacker — canivete offline pra estudar segurança: codificar/decodificar, hashes,
identificar hash, JWT, timestamps, geradores e inspeção de texto. Nada sai do PC."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from PyQt6.QtCore import Qt, QTimer  # noqa: E402
from PyQt6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap  # noqa: E402
from PyQt6.QtWidgets import (QApplication, QComboBox, QFileDialog, QFormLayout,  # noqa: E402
                             QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
                             QSpinBox, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                             QWidget)

from kh_tools import TOOLS  # noqa: E402

ACCENT = "#7c5cff"
QSS = """
QWidget { background:#11131a; color:#e7e9f0; font:10pt 'Segoe UI'; }
#title { font:700 18pt 'Segoe UI'; }
#info { color:#8a93a8; }
#err { color:#ff6b6b; }
QLineEdit, QComboBox, QSpinBox { background:#1b202b; border:1px solid #2d3550;
    border-radius:8px; padding:6px; }
QPlainTextEdit { background:#1b202b; border:1px solid #2d3550; border-radius:10px;
    font:10pt 'Consolas'; }
QPlainTextEdit#out { background:#0c0e14; color:#79e0a8; }
QTreeWidget { background:#161a23; border:1px solid #2d3550; border-radius:10px; padding:4px; }
QTreeWidget::item { padding:4px 2px; }
QTreeWidget::item:selected { background:#7c5cff; color:#fff; border-radius:6px; }
QPushButton { background:#222a38; border:0; border-radius:10px; padding:9px 14px; }
QPushButton:hover { background:#2d3550; }
#go { background:#7c5cff; color:#fff; font-weight:600; padding:12px 16px; font-size:12pt; }
#go:hover { background:#8f74ff; }
QSplitter::handle { background:#11131a; }
"""


def app_icon():
    pm = QPixmap(64, 64)
    pm.fill(QColor("transparent"))
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(ACCENT))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(8, 6, 48, 52, 14, 14)
    p.setPen(QColor("#ffffff"))
    p.setFont(QFont("Consolas", 22, QFont.Weight.Bold))
    p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, "</>")
    p.end()
    return QIcon(pm)


class KitHacker(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ Kit do Hacker")
        self.setWindowIcon(app_icon())
        self.resize(1050, 720)
        self.tool = None
        self.widgets = {}
        self.timer = QTimer(self, singleShot=True, interval=150)
        self.timer.timeout.connect(self.run)

        root = QHBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        split = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(split)

        # ---- esquerda: busca + árvore
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 8, 0)
        self.search = QLineEdit(placeholderText="🔎 Buscar função…")
        self.search.textChanged.connect(self._filter)
        lv.addWidget(self.search)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.items = {}
        cats = {}
        for t in TOOLS:
            if t["cat"] not in cats:
                ci = QTreeWidgetItem([t["cat"]])
                f = ci.font(0)
                f.setBold(True)
                ci.setFont(0, f)
                ci.setFlags(ci.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                self.tree.addTopLevelItem(ci)
                cats[t["cat"]] = ci
            it = QTreeWidgetItem([t["name"]])
            it.setData(0, Qt.ItemDataRole.UserRole, t["id"])
            cats[t["cat"]].addChild(it)
            self.items[t["id"]] = it
        self.tree.expandAll()
        self.tree.currentItemChanged.connect(self._picked)
        lv.addWidget(self.tree, 1)
        lv.addWidget(QLabel(f"{len(TOOLS)} funções · 100% offline", objectName="info"))
        split.addWidget(left)

        # ---- direita: painel da função
        right = QWidget()
        self.rv = QVBoxLayout(right)
        self.rv.setContentsMargins(8, 0, 0, 0)
        self.rv.setSpacing(8)
        self.title = QLabel("", objectName="title")
        self.desc = QLabel("", objectName="info", wordWrap=True)
        self.rv.addWidget(self.title)
        self.rv.addWidget(self.desc)
        self.form_host = QWidget()
        self.form_layout = QVBoxLayout(self.form_host)
        self.form_layout.setContentsMargins(0, 0, 0, 0)
        self.rv.addWidget(self.form_host, 2)
        self.go = QPushButton("▶  Executar", objectName="go")
        self.go.clicked.connect(self.run)
        self.rv.addWidget(self.go)
        orow = QHBoxLayout()
        orow.addWidget(QLabel("Resultado:"))
        orow.addStretch(1)
        self.status = QLabel("", objectName="info")
        orow.addWidget(self.status)
        cp = QPushButton("📋 Copiar")
        cp.clicked.connect(self.copy)
        orow.addWidget(cp)
        self.rv.addLayout(orow)
        self.out = QPlainTextEdit(objectName="out", readOnly=True)
        self.rv.addWidget(self.out, 3)
        split.addWidget(right)
        split.setSizes([270, 780])

        self.tree.setCurrentItem(self.items[TOOLS[0]["id"]])

    # ---- navegação
    def _filter(self, txt):
        q = txt.strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            cat = self.tree.topLevelItem(i)
            cat_hit = q in cat.text(0).lower()
            vis = 0
            for j in range(cat.childCount()):
                ch = cat.child(j)
                tid = ch.data(0, Qt.ItemDataRole.UserRole)
                t = next(x for x in TOOLS if x["id"] == tid)
                hit = not q or cat_hit or q in t["name"].lower() or q in t["desc"].lower()
                ch.setHidden(not hit)
                vis += hit
            cat.setHidden(vis == 0)

    def _picked(self, cur, _prev):
        if cur is None:
            return
        tid = cur.data(0, Qt.ItemDataRole.UserRole)
        if tid:
            self.select(tid)

    def select(self, tid):
        self.tool = next(t for t in TOOLS if t["id"] == tid)
        if self.tree.currentItem() is not self.items[tid]:
            self.tree.setCurrentItem(self.items[tid])
        self.title.setText(self.tool["name"])
        self.desc.setText(self.tool["desc"])
        self._build_form()
        self.out.clear()
        self.status.setText("")
        self.status.setObjectName("info")
        if self.tool["live"]:
            self.run()

    def _build_form(self):
        old = self.form_host
        self.form_host = QWidget()
        self.form_layout = QVBoxLayout(self.form_host)
        self.form_layout.setContentsMargins(0, 0, 0, 0)
        self.rv.replaceWidget(old, self.form_host)
        old.deleteLater()
        self.widgets = {}
        form = QFormLayout()
        self.form_layout.addLayout(form)
        live = self.tool["live"]
        for f in self.tool["fields"]:
            kind, key, label = f[0], f[1], f[2]
            if kind == "text":
                w = QPlainTextEdit(placeholderText=f[3])
                if live:
                    w.textChanged.connect(self.timer.start)
                self.form_layout.addWidget(QLabel(label))
                self.form_layout.addWidget(w, 1)
            elif kind == "line":
                w = QLineEdit(placeholderText=f[3])
                if live:
                    w.textChanged.connect(self.timer.start)
                form.addRow(label, w)
            elif kind == "combo":
                w = QComboBox()
                w.addItems(f[3])
                if live:
                    w.currentIndexChanged.connect(lambda *_: self.timer.start())
                form.addRow(label, w)
            elif kind == "spin":
                w = QSpinBox()
                w.setRange(f[3], f[4])
                w.setValue(f[5])
                form.addRow(label, w)
            elif kind == "file":
                row = QHBoxLayout()
                w = QLineEdit(placeholderText="nenhum arquivo escolhido")
                row.addWidget(w, 1)
                b = QPushButton("📂 Escolher…")
                b.clicked.connect(lambda _=False, le=w: self._pick_file(le))
                row.addWidget(b)
                form.addRow(label, row)
            else:
                continue
            self.widgets[key] = w

    def _pick_file(self, le):
        path, _ = QFileDialog.getOpenFileName(self, "Escolher arquivo")
        if path:
            le.setText(path)
            self.run()

    # ---- execução
    def values(self):
        v = {}
        for k, w in self.widgets.items():
            if isinstance(w, QPlainTextEdit):
                v[k] = w.toPlainText()
            elif isinstance(w, QLineEdit):
                v[k] = w.text()
            elif isinstance(w, QComboBox):
                v[k] = w.currentText()
            elif isinstance(w, QSpinBox):
                v[k] = w.value()
        return v

    def set_value(self, key, value):
        w = self.widgets[key]
        if isinstance(w, QPlainTextEdit):
            w.setPlainText(value)
        elif isinstance(w, QLineEdit):
            w.setText(value)
        elif isinstance(w, QComboBox):
            w.setCurrentText(value)
        elif isinstance(w, QSpinBox):
            w.setValue(int(value))

    def run(self):
        if not self.tool:
            return
        self.timer.stop()
        try:
            res = self.tool["run"](self.values())
            self.out.setPlainText(res)
            self.status.setText("")
            ok = True
        except Exception as e:  # mostra o erro sem derrubar o app
            self.out.setPlainText("")
            self.status.setText(f"⚠ Entrada inválida: {e}")
            ok = False
        self.status.setObjectName("info" if ok else "err")
        self.status.setStyleSheet("")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        return ok

    def copy(self):
        QApplication.clipboard().setText(self.out.toPlainText())
        self.status.setText("Copiado! ✔")


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    w = KitHacker()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
