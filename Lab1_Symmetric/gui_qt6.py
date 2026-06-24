#!/usr/bin/env python3
"""
Lab 1 AES GUI - Production-Ready with Light Theme (bonus +5 points)
Features: Encryption/Decryption, File I/O, Benchmarking, Unit Tests, NIST KAT Validation
Uses ctypes to call aestool.dll - does NOT duplicate cryptographic logic
"""

import sys
import os
import json
import base64
import ctypes
import secrets
import subprocess
import threading
import time
from pathlib import Path
from ctypes import POINTER, c_ubyte, c_int, c_char_p, byref
from datetime import datetime

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# ─── MinGW / DLL resolution ──────────────────────────────────────────────────
if sys.platform == "win32":
    mingw_path = r"C:\msys64\mingw64\bin"
    if os.path.exists(mingw_path):
        try:
            os.add_dll_directory(mingw_path)
        except AttributeError:
            pass
        os.environ["PATH"] = mingw_path + os.pathsep + os.environ["PATH"]


# ─── DLL loader ───────────────────────────────────────────────────────────────
def load_crypto_dll():
    """Auto-detect and load aestool.dll or cryptocore.dll"""
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base, "build", "aestool.dll"),
        os.path.join(base, "build", "msys-cryptocore.dll"),
        os.path.join(base, "build", "cryptocore.dll"),
        os.path.join(base, "build", "Release", "aestool.dll"),
        os.path.join(base, "build", "Debug", "aestool.dll"),
        os.path.join(base, "aestool.dll"),
        os.path.join(base, "msys-cryptocore.dll"),
        os.path.join(base, "cryptocore.dll"),
        os.path.join(base, "build", "libaestool.so"),
        os.path.join(base, "build", "libcryptocore.so"),
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                dll = ctypes.CDLL(p)
                return dll, p
            except Exception as e:
                print(f"[DLL] Failed {p}: {e}")
    return None, None


def resolve_exe_path(build_dir, exe_name):
    """Auto-detect executable in MSVC build/Release or build/Debug subdirectories"""
    # Try direct path first (MinGW / single-config builds)
    direct = os.path.join(build_dir, exe_name)
    if os.path.exists(direct):
        return direct
    
    # Try MSVC multi-config subdirectories
    for config in ["Release", "Debug", "RelWithDebInfo", "MinSizeRel"]:
        candidate = os.path.join(build_dir, config, exe_name)
        if os.path.exists(candidate):
            return candidate
    
    # Return direct path (will fail with clear error message later)
    return direct


def configure_dll(dll):
    """Attach argtypes / restype to the exported AES functions."""
    dll.encrypt_aes_c.argtypes = [
        c_char_p,          # mode
        POINTER(c_ubyte),  # plaintext
        c_int,             # plaintext_len
        POINTER(c_ubyte),  # key
        c_int,             # key_len
        POINTER(c_ubyte),  # iv
        c_int,             # iv_len
        c_char_p,          # aad
        c_int,             # is_aead
        c_int,             # allow_ecb
        POINTER(c_ubyte),  # ciphertext_out
        POINTER(c_int),    # ciphertext_len_out
        POINTER(c_ubyte),  # key_out
        POINTER(c_int),    # key_len_out
        POINTER(c_ubyte),  # iv_out
        POINTER(c_int),    # iv_len_out
        POINTER(c_ubyte),  # tag_out
        POINTER(c_int),    # tag_len_out
        c_char_p,          # err_msg_out
    ]
    dll.encrypt_aes_c.restype = c_int

    dll.decrypt_aes_c.argtypes = [
        c_char_p,          # mode
        POINTER(c_ubyte),  # ciphertext
        c_int,             # ciphertext_len
        POINTER(c_ubyte),  # key
        c_int,             # key_len
        POINTER(c_ubyte),  # iv
        c_int,             # iv_len
        c_char_p,          # aad
        POINTER(c_ubyte),  # tag
        c_int,             # tag_len
        c_int,             # is_aead
        POINTER(c_ubyte),  # plaintext_out
        POINTER(c_int),    # plaintext_len_out
        c_char_p,          # err_msg_out
    ]
    dll.decrypt_aes_c.restype = c_int

    dll.lab1_run_kat.argtypes = [
        c_char_p,          # vectors_file
        c_char_p,          # error_msg
    ]
    dll.lab1_run_kat.restype = c_char_p


# Auto-load DLL at startup
dll, dll_path = load_crypto_dll()
if dll:
    configure_dll(dll)


# ─── Worker Threads ───────────────────────────────────────────────────────────
class BenchmarkWorker(QThread):
    """Runs benchmark operations in a background thread"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(list)
    
    def __init__(self, build_dir, mode=None, size=None, threads=None):
        super().__init__()
        self.build_dir = build_dir
        self.mode = mode
        self.size = size
        self.threads = threads
    
    def run(self):
        try:
            exe = resolve_exe_path(self.build_dir, "benchmark.exe")
            if not os.path.exists(exe):
                self.progress.emit(f"[ERROR] Benchmark executable not found: {exe}")
                self.progress.emit(f"[HINT] Build with: cmake --build . --config Release")
                self.finished.emit([])
                return
            
            cmd = [exe]
            if self.mode:
                cmd.extend(["--mode", self.mode])
            if self.size:
                cmd.extend(["--size", str(self.size)])
            cmd.extend(["--threads", str(self.threads if self.threads is not None else 0)])
            
            self.progress.emit(f"[*] Running: {' '.join(cmd)}")
            self.progress.emit(f"[*] Build directory: {self.build_dir}")
            self.progress.emit("[*] This may take several minutes (be patient!)...")
            self.progress.emit("")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=self.build_dir
            )
            
            results = []
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                line = line.rstrip()
                if line:
                    self.progress.emit(line)
                    results.append(line)
            
            process.wait()
            self.progress.emit("")
            self.progress.emit(f"[+] Benchmark complete (exit code: {process.returncode})")
            self.finished.emit(results)
            
        except Exception as e:
            self.progress.emit(f"[ERROR] Benchmark failed: {e}")
            self.finished.emit([])


class TestWorker(QThread):
    """Runs Catch2 unit tests in a background thread"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(int, int, int)
    
    def __init__(self, build_dir):
        super().__init__()
        self.build_dir = build_dir
    
    def run(self):
        try:
            exe = resolve_exe_path(self.build_dir, "catch2_test.exe")
            if not os.path.exists(exe):
                self.progress.emit(f"[ERROR] Test executable not found: {exe}")
                self.progress.emit(f"[HINT] Build with: cmake --build . --config Release")
                self.finished.emit(0, 0, 0)
                return
            
            self.progress.emit(f"[*] Running: {exe}")
            
            process = subprocess.Popen(
                [exe],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=self.build_dir
            )
            
            total = passed = failed = 0
            for line in process.stdout:
                line = line.rstrip()
                self.progress.emit(line)
                
                if "test cases:" in line:
                    try:
                        parts = line.split("|")
                        total = int(parts[0].split(":")[1].strip())
                        passed = int(parts[1].split("passed")[0].strip())
                        failed = int(parts[2].split("failed")[0].strip())
                    except:
                        pass
            
            process.wait()
            self.progress.emit(f"[+] Tests complete (exit code: {process.returncode})")
            self.finished.emit(total, passed, failed)
            
        except Exception as e:
            self.progress.emit(f"[ERROR] Tests failed: {e}")
            self.finished.emit(0, 0, 0)


class KatWorker(QThread):
    """Runs NIST KAT validation via DLL lab1_run_kat in a background thread"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(int, int, int)

    def __init__(self, vectors_path):
        super().__init__()
        self.vectors_path = vectors_path

    def run(self):
        try:
            self.progress.emit(f"[*] Running NIST KAT validation via DLL...")
            self.progress.emit(f"[*] Vectors: {self.vectors_path}")

            errbuf = ctypes.create_string_buffer(1024)
            result = dll.lab1_run_kat(
                self.vectors_path.encode(),
                errbuf
            )

            if result:
                output = result.decode('utf-8', errors='replace')
                total = passed = failed = 0

                for line in output.splitlines():
                    stripped = line.rstrip()
                    if stripped:
                        self.progress.emit(stripped)
                    # Parse summary: "  TOTAL: 14 | PASSED: 14 | FAILED: 0"
                    if "TOTAL:" in stripped and "PASSED:" in stripped:
                        try:
                            parts = stripped.split("|")
                            total = int(parts[0].split(":")[1].strip())
                            passed = int(parts[1].split(":")[1].strip())
                            failed = int(parts[2].split(":")[1].strip())
                        except:
                            pass

                self.finished.emit(total, passed, failed)
            else:
                err = errbuf.value.decode('utf-8', errors='replace')
                self.progress.emit(f"[ERROR] lab1_run_kat failed: {err}")
                self.finished.emit(0, 0, 0)

        except Exception as e:
            self.progress.emit(f"[ERROR] KAT failed: {e}")
            self.finished.emit(0, 0, 0)


# ─── Stylesheet ───────────────────────────────────────────────────────────────
QSS = """
QMainWindow { background: #F5F7FA; }
QWidget      { background: #F5F7FA; }

/* Tabs */
QTabWidget::pane {
    border: 1px solid #D0D8E8;
    border-radius: 6px;
    background: #FFFFFF;
}
QTabBar::tab {
    background: #E8EBF0;
    color: #1A1A2E;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: bold;
}
QTabBar::tab:selected {
    background: #0077B6;
    color: #FFFFFF;
}
QTabBar::tab:hover:!selected {
    background: #D0E8F5;
}

/* Cards */
QFrame#card {
    background: #FFFFFF;
    border: 1px solid #D0D8E8;
    border-radius: 8px;
}

/* Labels */
QLabel { color: #1A1A2E; font-size: 14px; }
QLabel#title_lbl  { color: #0077B6; font-size: 23px; font-weight: bold; }
QLabel#sub_lbl    { color: #666699; font-size: 13px; font-style: italic; }
QLabel#card_title { color: #0077B6; font-size: 15px; font-weight: bold; }
QLabel#log_header { color: #0077B6; font-size: 13px; font-weight: bold; }
QLabel#stat_label { color: #2D6A4F; font-size: 14px; font-weight: bold; }

/* Inputs */
QLineEdit {
    background: #F0F4F8;
    border: 1px solid #C0C0C0;
    border-radius: 4px;
    padding: 4px 8px;
    color: #1A1A2E;
    font-size: 14px;
}
QLineEdit:focus  { border: 1px solid #0077B6; background: #E0EEF8; }
QLineEdit:disabled { background: #E8EBF0; color: #909090; }

QComboBox {
    background: #F0F4F8;
    border: 1px solid #C0C0C0;
    border-radius: 4px;
    padding: 4px 8px;
    color: #1A1A2E;
    font-size: 14px;
    min-width: 90px;
}
QComboBox:focus { border: 1px solid #0077B6; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView {
    background: #FFFFFF;
    border: 1px solid #0077B6;
    selection-background-color: #D0E8F5;
    color: #1A1A2E;
}

/* Buttons */
QPushButton {
    background: #0077B6;
    color: #FFFFFF;
    border: none;
    border-radius: 5px;
    padding: 6px 14px;
    font-size: 14px;
    font-weight: bold;
}
QPushButton:hover   { background: #005F92; }
QPushButton:pressed { background: #004A73; }
QPushButton:disabled { background: #A0A0A0; }
QPushButton#action_btn {
    background: #2D6A4F;
    font-size: 16px;
    padding: 10px 20px;
}
QPushButton#action_btn:hover   { background: #40916C; }
QPushButton#action_btn:pressed { background: #1B4332; }
QPushButton#bench_btn {
    background: #E76F51;
    font-size: 15px;
    padding: 8px 18px;
}
QPushButton#bench_btn:hover   { background: #F4A261; }
QPushButton#bench_btn:pressed { background: #E76F51; }
QPushButton#test_btn {
    background: #6A0572;
    font-size: 15px;
    padding: 8px 18px;
}
QPushButton#test_btn:hover   { background: #AB83A1; }
QPushButton#test_btn:pressed { background: #6A0572; }

/* Checkboxes / Radios */
QRadioButton, QCheckBox { color: #1A1A2E; font-size: 14px; spacing: 6px; }

/* Text areas */
QTextEdit {
    background: #F0F4F8;
    border: 1px solid #D0D8E8;
    border-radius: 4px;
    color: #1A1A2E;
    font-family: "Courier New";
    font-size: 13px;
}
QTextEdit#output_text { background: #EAF4FB; color: #0077B6; }
QTextEdit#log_text    { background: #F8FAFF; color: #333333; font-size: 12px; }
QTextEdit#bench_text  { background: #FFF8F0; color: #E76F51; font-size: 12px; }
QTextEdit#test_text   { background: #F8F0FF; color: #6A0572; font-size: 12px; }

/* Tables */
QTableWidget {
    background: #FFFFFF;
    border: 1px solid #D0D8E8;
    border-radius: 4px;
    gridline-color: #D0D8E8;
}
QTableWidget::item { padding: 4px; }
QTableWidget::item:selected { background: #D0E8F5; color: #0077B6; }
QHeaderView::section {
    background: #0077B6;
    color: #FFFFFF;
    padding: 6px;
    border: none;
    font-weight: bold;
}

/* Progress bar */
QProgressBar {
    border: 1px solid #D0D8E8;
    border-radius: 4px;
    text-align: center;
    background: #F0F4F8;
}
QProgressBar::chunk {
    background: #0077B6;
    border-radius: 3px;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #F0F4F8; width: 10px; border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #B0C4D8; border-radius: 5px; min-height: 28px;
}
QScrollBar::handle:vertical:hover { background: #0077B6; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background: #F0F4F8; height: 10px; border-radius: 5px;
}
QScrollBar::handle:horizontal {
    background: #B0C4D8; border-radius: 5px; min-width: 28px;
}
QScrollBar::handle:horizontal:hover { background: #0077B6; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* Splitter */
QSplitter::handle { background: #D0D8E8; }
"""


# ─── Helpers ─────────────────────────────────────────────────────────────────
def card_widget() -> QFrame:
    f = QFrame()
    f.setObjectName("card")
    return f


def card_title(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("card_title")
    return lbl


# ─── Main Window ──────────────────────────────────────────────────────────────
class CryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES Symmetric Encryption Tool - Lab 1")
        self.resize(1280, 900)

        root = QWidget()
        self.setCentralWidget(root)
        main_vbox = QVBoxLayout(root)
        main_vbox.setContentsMargins(12, 10, 12, 10)
        main_vbox.setSpacing(8)

        main_vbox.addWidget(self._build_header())
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_crypto_tab(), "Encrypt/Decrypt")
        self.tabs.addTab(self._build_benchmark_tab(), "Benchmark")
        self.tabs.addTab(self._build_tests_tab(), "Unit Tests")
        self.tabs.addTab(self._build_kat_tab(), "NIST KAT")
        main_vbox.addWidget(self.tabs, stretch=1)

        main_vbox.addWidget(self._build_log_panel())

        # Workers
        self.bench_worker = None
        self.test_worker = None
        self.kat_worker = None
        
        self.update_ui_state()
        self._post_init()

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)

        title = QLabel("AES SYMMETRIC ENCRYPTION TOOL")
        title.setObjectName("title_lbl")

        sub = QLabel("C++ Core & Python ctypes Integration")
        sub.setObjectName("sub_lbl")

        h.addWidget(title)
        h.addSpacing(12)
        h.addWidget(sub, alignment=Qt.AlignmentFlag.AlignVCenter)
        h.addStretch()
        return w

    # ── Tab 1: Encryption/Decryption ─────────────────────────────────────────
    def _build_crypto_tab(self) -> QScrollArea:
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.Shape.NoFrame)
        
        inner = QWidget()
        vbox = QVBoxLayout(inner)
        vbox.setContentsMargins(8, 8, 8, 8)
        vbox.setSpacing(10)
        
        # Left-right split for crypto tab
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        
        # Left panel
        left = QWidget()
        left_vbox = QVBoxLayout(left)
        left_vbox.setContentsMargins(0, 0, 0, 0)
        left_vbox.setSpacing(10)
        left_vbox.addWidget(self._card_lib())
        left_vbox.addWidget(self._card_cipher())
        left_vbox.addWidget(self._card_params())
        left_vbox.addStretch()
        
        # Right panel
        right = QWidget()
        right_vbox = QVBoxLayout(right)
        right_vbox.setContentsMargins(0, 0, 0, 0)
        right_vbox.setSpacing(10)
        right_vbox.addWidget(self._card_input(), stretch=1)
        right_vbox.addWidget(self._card_output(), stretch=1)
        right_vbox.addWidget(self._build_action_btn())
        
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([380, 720])
        
        vbox.addWidget(splitter, stretch=1)
        sa.setWidget(inner)
        return sa

    # ── Card: Library Config ──────────────────────────────────────────────────
    def _card_lib(self) -> QFrame:
        card = card_widget()
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(14, 12, 14, 12)
        vbox.setSpacing(7)

        vbox.addWidget(card_title("Core Library Configuration"))
        vbox.addWidget(QLabel("Library DLL Path:"))

        self.lib_path_entry = QLineEdit()
        self.lib_path_entry.setPlaceholderText("No DLL loaded — click Browse to choose…")
        if dll_path:
            self.lib_path_entry.setText(dll_path)
        vbox.addWidget(self.lib_path_entry)

        btn_row = QHBoxLayout()
        b_browse = QPushButton("Browse DLL")
        b_browse.clicked.connect(self.browse_lib_dll)
        b_load = QPushButton("Load DLL")
        b_load.clicked.connect(self.load_custom_dll)
        btn_row.addWidget(b_browse)
        btn_row.addWidget(b_load)
        btn_row.addStretch()
        vbox.addLayout(btn_row)
        return card

    # ── Card: Cipher Config ───────────────────────────────────────────────────
    def _card_cipher(self) -> QFrame:
        card = card_widget()
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(14, 12, 14, 12)
        vbox.setSpacing(7)

        vbox.addWidget(card_title("Cipher Configuration"))

        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Operation Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["ecb", "cbc", "ctr", "ofb", "cfb", "xts", "gcm", "ccm"])
        self.mode_combo.setCurrentText("cbc")
        self.mode_combo.currentTextChanged.connect(self.update_ui_state)
        mode_row.addWidget(self.mode_combo)
        mode_row.addStretch()
        vbox.addLayout(mode_row)

        vbox.addWidget(QLabel("Operation Direction:"))
        self._dir_group = QButtonGroup(self)
        dir_row = QHBoxLayout()
        self.rb_encrypt = QRadioButton("Encrypt")
        self.rb_encrypt.setChecked(True)
        self.rb_decrypt = QRadioButton("Decrypt")
        self._dir_group.addButton(self.rb_encrypt)
        self._dir_group.addButton(self.rb_decrypt)
        self.rb_encrypt.toggled.connect(self.update_ui_state)
        dir_row.addWidget(self.rb_encrypt)
        dir_row.addWidget(self.rb_decrypt)
        dir_row.addStretch()
        vbox.addLayout(dir_row)
        return card

    # ── Card: Key & IV ────────────────────────────────────────────────────────
    def _card_params(self) -> QFrame:
        card = card_widget()
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(14, 12, 14, 12)
        vbox.setSpacing(7)

        vbox.addWidget(card_title("Key & IV Parameters"))

        fmt_row = QHBoxLayout()
        fmt_row.addWidget(QLabel("Key Format:"))
        self.key_format_combo = QComboBox()
        self.key_format_combo.addItems(["hex", "text"])
        fmt_row.addWidget(self.key_format_combo)
        fmt_row.addStretch()
        vbox.addLayout(fmt_row)

        vbox.addWidget(QLabel("Key (empty = auto-generate):"))
        self.key_entry = QLineEdit()
        self.key_entry.setPlaceholderText("Leave empty for random key")
        vbox.addWidget(self.key_entry)

        vbox.addWidget(QLabel("IV / Nonce (empty = auto-generate):"))
        self.iv_entry = QLineEdit()
        self.iv_entry.setPlaceholderText("Leave empty for random IV (hex)")
        vbox.addWidget(self.iv_entry)

        self.aad_label = QLabel("AAD (GCM/CCM only):")
        self.aad_entry = QLineEdit()
        self.aad_entry.setPlaceholderText("Additional Authenticated Data")
        vbox.addWidget(self.aad_label)
        vbox.addWidget(self.aad_entry)

        self.tag_label = QLabel("Authentication Tag (Hex):")
        self.tag_entry = QLineEdit()
        self.tag_entry.setPlaceholderText("Auth tag (hex string)")
        vbox.addWidget(self.tag_label)
        vbox.addWidget(self.tag_entry)

        self.allow_ecb_check = QCheckBox("Allow insecure ECB > 16 KiB")
        vbox.addWidget(self.allow_ecb_check)
        return card

    # ── Card: KAT ─────────────────────────────────────────────────────────────
    def _card_kat(self) -> QFrame:
        card = card_widget()
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(14, 12, 14, 12)
        vbox.setSpacing(7)

        vbox.addWidget(card_title("NIST Known Answer Tests (KAT)"))
        vbox.addWidget(QLabel("Vectors JSON Path:"))

        self.kat_path_entry = QLineEdit()
        self.kat_path_entry.setPlaceholderText("Path to vectors.json\u2026")
        _base = os.path.dirname(os.path.abspath(__file__))
        for p in ["test_vectors/vectors.json", "build/vectors.json", "vectors.json"]:
            full = os.path.join(_base, p)
            if os.path.exists(full):
                self.kat_path_entry.setText(full)
                break
        vbox.addWidget(self.kat_path_entry)

        btn_row = QHBoxLayout()
        b_browse = QPushButton("Browse")
        b_browse.clicked.connect(self.browse_kat_file)
        b_run = QPushButton("Run KAT")
        b_run.clicked.connect(self.execute_kat_test)
        btn_row.addWidget(b_browse)
        btn_row.addWidget(b_run)
        btn_row.addStretch()
        vbox.addLayout(btn_row)
        return card

    # ── Tab 2: Benchmark ─────────────────────────────────────────────────────
    def _build_benchmark_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(12, 12, 12, 12)
        vbox.setSpacing(12)
        
        # Config card
        config_card = card_widget()
        config_vbox = QVBoxLayout(config_card)
        config_vbox.setContentsMargins(14, 12, 14, 12)
        config_vbox.setSpacing(8)
        
        config_vbox.addWidget(card_title("Benchmark Configuration"))
        
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Mode:"))
        self.bench_mode_combo = QComboBox()
        self.bench_mode_combo.addItems(["All Modes", "ecb", "cbc", "ctr", "ofb", "cfb", "xts", "gcm", "ccm"])
        mode_row.addWidget(self.bench_mode_combo)
        mode_row.addStretch()
        config_vbox.addLayout(mode_row)
        
        size_row = QHBoxLayout()
        size_row.addWidget(QLabel("Payload Size:"))
        self.bench_size_combo = QComboBox()
        self.bench_size_combo.addItems(["All Sizes", "1 KB", "4 KB", "16 KB", "256 KB", "1 MB", "8 MB"])
        size_row.addWidget(self.bench_size_combo)
        size_row.addStretch()
        config_vbox.addLayout(size_row)
        
        thread_row = QHBoxLayout()
        thread_row.addWidget(QLabel("Threads:"))
        self.bench_threads_combo = QComboBox()
        self.bench_threads_combo.addItems(["Auto", "1", "2", "4", "8", "12", "16", "20", "24", "32"])
        thread_row.addWidget(self.bench_threads_combo)
        thread_row.addStretch()
        config_vbox.addLayout(thread_row)
        
        btn_row = QHBoxLayout()
        self.bench_btn = QPushButton("▶ Run Benchmark")
        self.bench_btn.setObjectName("bench_btn")
        self.bench_btn.clicked.connect(self.run_benchmark)
        self.bench_stop_btn = QPushButton("■ Stop")
        self.bench_stop_btn.setEnabled(False)
        self.bench_stop_btn.clicked.connect(self.stop_benchmark)
        btn_row.addWidget(self.bench_btn)
        btn_row.addWidget(self.bench_stop_btn)
        btn_row.addStretch()
        config_vbox.addLayout(btn_row)
        
        vbox.addWidget(config_card)
        
        # Output area
        output_card = card_widget()
        output_vbox = QVBoxLayout(output_card)
        output_vbox.setContentsMargins(14, 12, 14, 12)
        output_vbox.setSpacing(4)
        
        output_vbox.addWidget(card_title("Benchmark Results"))
        self.bench_text = QTextEdit()
        self.bench_text.setObjectName("bench_text")
        self.bench_text.setReadOnly(True)
        self.bench_text.setPlaceholderText("Benchmark results will appear here...")
        output_vbox.addWidget(self.bench_text, stretch=1)
        
        vbox.addWidget(output_card, stretch=1)
        return w

    # ── Tab 3: Unit Tests ────────────────────────────────────────────────────
    def _build_tests_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(12, 12, 12, 12)
        vbox.setSpacing(12)
        
        # Control card
        control_card = card_widget()
        control_vbox = QVBoxLayout(control_card)
        control_vbox.setContentsMargins(14, 12, 14, 12)
        control_vbox.setSpacing(8)
        
        control_vbox.addWidget(card_title("Catch2 Unit Tests"))
        control_vbox.addWidget(QLabel("Runs comprehensive AES encryption/decryption tests including NIST vectors"))
        
        btn_row = QHBoxLayout()
        self.test_btn = QPushButton("▶ Run All Tests")
        self.test_btn.setObjectName("test_btn")
        self.test_btn.clicked.connect(self.run_tests)
        self.test_stop_btn = QPushButton("■ Stop")
        self.test_stop_btn.setEnabled(False)
        self.test_stop_btn.clicked.connect(self.stop_tests)
        btn_row.addWidget(self.test_btn)
        btn_row.addWidget(self.test_stop_btn)
        btn_row.addStretch()
        control_vbox.addLayout(btn_row)
        
        # Stats row
        stats_row = QHBoxLayout()
        self.test_total_lbl = QLabel("Total: --")
        self.test_total_lbl.setObjectName("stat_label")
        self.test_passed_lbl = QLabel("Passed: --")
        self.test_passed_lbl.setObjectName("stat_label")
        self.test_failed_lbl = QLabel("Failed: --")
        self.test_failed_lbl.setObjectName("stat_label")
        stats_row.addWidget(self.test_total_lbl)
        stats_row.addSpacing(20)
        stats_row.addWidget(self.test_passed_lbl)
        stats_row.addSpacing(20)
        stats_row.addWidget(self.test_failed_lbl)
        stats_row.addStretch()
        control_vbox.addLayout(stats_row)
        
        vbox.addWidget(control_card)
        
        # Output area
        output_card = card_widget()
        output_vbox = QVBoxLayout(output_card)
        output_vbox.setContentsMargins(14, 12, 14, 12)
        output_vbox.setSpacing(4)
        
        output_vbox.addWidget(card_title("Test Output"))
        self.test_text = QTextEdit()
        self.test_text.setObjectName("test_text")
        self.test_text.setReadOnly(True)
        self.test_text.setPlaceholderText("Test results will appear here...")
        output_vbox.addWidget(self.test_text, stretch=1)
        
        vbox.addWidget(output_card, stretch=1)
        return w

    # ── Tab 4: NIST KAT ──────────────────────────────────────────────────────
    def _build_kat_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(12, 12, 12, 12)
        vbox.setSpacing(12)
        
        # Config card
        config_card = card_widget()
        config_vbox = QVBoxLayout(config_card)
        config_vbox.setContentsMargins(14, 12, 14, 12)
        config_vbox.setSpacing(8)
        
        config_vbox.addWidget(card_title("NIST Known Answer Tests Configuration"))
        
        vbox_path = QVBoxLayout()
        vbox_path.addWidget(QLabel("Vectors JSON File:"))
        path_row = QHBoxLayout()
        self.kat_path_entry = QLineEdit()
        self.kat_path_entry.setPlaceholderText("Path to vectors.json\u2026")
        _base = os.path.dirname(os.path.abspath(__file__))
        for p in ["SampleData/vectors.json", "build/vectors.json", "vectors.json"]:
            full = os.path.join(_base, p)
            if os.path.exists(full):
                self.kat_path_entry.setText(full)
                break
        path_row.addWidget(self.kat_path_entry)
        b_browse = QPushButton("Browse")
        b_browse.clicked.connect(self.browse_kat_file)
        path_row.addWidget(b_browse)
        vbox_path.addLayout(path_row)
        config_vbox.addLayout(vbox_path)
        
        btn_row = QHBoxLayout()
        self.kat_run_btn = QPushButton("▶ Run KAT Validation")
        self.kat_run_btn.setObjectName("action_btn")
        self.kat_run_btn.clicked.connect(self.execute_kat_test)
        self.kat_stop_btn = QPushButton("■ Stop")
        self.kat_stop_btn.setEnabled(False)
        self.kat_stop_btn.clicked.connect(self.stop_kat)
        btn_row.addWidget(self.kat_run_btn)
        btn_row.addWidget(self.kat_stop_btn)
        btn_row.addStretch()
        config_vbox.addLayout(btn_row)
        
        # Stats row
        stats_row = QHBoxLayout()
        self.kat_total_lbl = QLabel("Total: --")
        self.kat_total_lbl.setObjectName("stat_label")
        self.kat_passed_lbl = QLabel("Passed: --")
        self.kat_passed_lbl.setObjectName("stat_label")
        self.kat_failed_lbl = QLabel("Failed: --")
        self.kat_failed_lbl.setObjectName("stat_label")
        stats_row.addWidget(self.kat_total_lbl)
        stats_row.addSpacing(20)
        stats_row.addWidget(self.kat_passed_lbl)
        stats_row.addSpacing(20)
        stats_row.addWidget(self.kat_failed_lbl)
        stats_row.addStretch()
        config_vbox.addLayout(stats_row)
        
        vbox.addWidget(config_card)
        
        # Results area
        output_card = card_widget()
        output_vbox = QVBoxLayout(output_card)
        output_vbox.setContentsMargins(14, 12, 14, 12)
        output_vbox.setSpacing(4)
        
        output_vbox.addWidget(card_title("KAT Results"))
        self.kat_text = QTextEdit()
        self.kat_text.setObjectName("bench_text")
        self.kat_text.setReadOnly(True)
        self.kat_text.setPlaceholderText("KAT validation results will appear here...")
        output_vbox.addWidget(self.kat_text, stretch=1)
        
        vbox.addWidget(output_card, stretch=1)
        return w

    # ── Right panel ───────────────────────────────────────────────────────────
    def _build_right_panel(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(10)
        vbox.addWidget(self._card_input(), stretch=1)
        vbox.addWidget(self._card_output(), stretch=1)
        vbox.addWidget(self._build_action_btn())
        return w

    # ── Card: Input ───────────────────────────────────────────────────────────
    def _card_input(self) -> QFrame:
        card = card_widget()
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(14, 12, 14, 12)
        vbox.setSpacing(7)

        title_row = QHBoxLayout()
        title_row.addWidget(card_title("Input Data"))
        title_row.addSpacing(16)

        self._in_grp = QButtonGroup(self)
        self.rb_in_text = QRadioButton("Direct Text")
        self.rb_in_text.setChecked(True)
        self.rb_in_file = QRadioButton("File Path")
        self._in_grp.addButton(self.rb_in_text)
        self._in_grp.addButton(self.rb_in_file)
        self.rb_in_text.toggled.connect(self.update_ui_state)
        title_row.addWidget(self.rb_in_text)
        title_row.addWidget(self.rb_in_file)
        title_row.addStretch()
        vbox.addLayout(title_row)

        self.text_in = QTextEdit()
        self.text_in.setPlaceholderText("Enter plaintext (encrypt) or hex/base64 ciphertext (decrypt)…")
        vbox.addWidget(self.text_in, stretch=1)

        self.file_in_w = QWidget()
        fr = QHBoxLayout(self.file_in_w)
        fr.setContentsMargins(0, 0, 0, 0)
        self.file_in_entry = QLineEdit()
        self.file_in_entry.setPlaceholderText("Input file path…")
        b = QPushButton("Browse")
        b.clicked.connect(self.browse_input_file)
        fr.addWidget(self.file_in_entry)
        fr.addWidget(b)
        vbox.addWidget(self.file_in_w)

        self.in_fmt_row = QWidget()
        ifr = QHBoxLayout(self.in_fmt_row)
        ifr.setContentsMargins(0, 0, 0, 0)
        self.in_fmt_label = QLabel("Input Text Format:")
        self.input_format_combo = QComboBox()
        self.input_format_combo.addItems(["text", "hex", "base64"])
        ifr.addWidget(self.in_fmt_label)
        ifr.addWidget(self.input_format_combo)
        ifr.addStretch()
        vbox.addWidget(self.in_fmt_row)

        self.out_fmt_row = QWidget()
        ofr = QHBoxLayout(self.out_fmt_row)
        ofr.setContentsMargins(0, 0, 0, 0)
        self.out_fmt_label = QLabel("Output Text Format:")
        self.output_format_combo = QComboBox()
        self.output_format_combo.addItems(["hex", "base64", "raw"])
        ofr.addWidget(self.out_fmt_label)
        ofr.addWidget(self.output_format_combo)
        ofr.addStretch()
        vbox.addWidget(self.out_fmt_row)
        return card

    # ── Card: Output ──────────────────────────────────────────────────────────
    def _card_output(self) -> QFrame:
        card = card_widget()
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(14, 12, 14, 12)
        vbox.setSpacing(7)

        vbox.addWidget(card_title("Output Result"))

        self.text_out = QTextEdit()
        self.text_out.setObjectName("output_text")
        self.text_out.setReadOnly(True)
        self.text_out.setPlaceholderText("Result appears here…")
        vbox.addWidget(self.text_out, stretch=1)

        self.file_out_w = QWidget()
        fr = QHBoxLayout(self.file_out_w)
        fr.setContentsMargins(0, 0, 0, 0)
        self.file_out_entry = QLineEdit()
        self.file_out_entry.setPlaceholderText("Output file path…")
        b = QPushButton("Browse")
        b.clicked.connect(self.browse_output_file)
        fr.addWidget(self.file_out_entry)
        fr.addWidget(b)
        vbox.addWidget(self.file_out_w)
        return card

    # ── Action button ─────────────────────────────────────────────────────────
    def _build_action_btn(self) -> QPushButton:
        self.action_btn = QPushButton("RUN AES-CBC ENCRYPT")
        self.action_btn.setObjectName("action_btn")
        self.action_btn.setMinimumHeight(48)
        self.action_btn.clicked.connect(self.execute_crypto)
        return self.action_btn

    # ── Log panel ─────────────────────────────────────────────────────────────
    def _build_log_panel(self) -> QFrame:
        card = card_widget()
        card.setFixedHeight(170)
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(12, 8, 12, 8)
        vbox.setSpacing(4)

        hdr = QLabel("Execution Log / Native Standard Output")
        hdr.setObjectName("log_header")
        vbox.addWidget(hdr)

        self.log_text = QTextEdit()
        self.log_text.setObjectName("log_text")
        self.log_text.setReadOnly(True)
        vbox.addWidget(self.log_text)
        return card

    # ─── Post init ────────────────────────────────────────────────────────────
    def _post_init(self):
        if not dll:
            self.log("CRITICAL: aestool.dll could not be loaded.", "#D62828")
            self.log("Build with: cmake --build build --target aestool_lib", "#D62828")
            QMessageBox.critical(
                self, "Library Load Error",
                "Could not find or load 'aestool.dll'.\n"
                "Run CMake to build the shared library first."
            )
        else:
            self.log(f"[OK] Loaded native library: {dll_path}", "#2D6A4F")

    # ─── UI State ─────────────────────────────────────────────────────────────
    def update_ui_state(self):
        mode      = self.mode_combo.currentText()
        is_enc    = self.rb_encrypt.isChecked()
        in_text   = self.rb_in_text.isChecked()
        is_aead   = mode in ("gcm", "ccm")
        is_ecb    = mode == "ecb"

        # AEAD fields
        self.aad_label.setVisible(is_aead)
        self.aad_entry.setVisible(is_aead)
        self.tag_label.setVisible(is_aead)
        self.tag_entry.setVisible(is_aead)
        if is_aead:
            self.tag_label.setText("Generated Tag (Hex):" if is_enc else "Input Tag (Hex – Required):")

        # ECB / IV
        self.iv_entry.setEnabled(not is_ecb)
        self.allow_ecb_check.setVisible(is_ecb)

        # Input / output mode
        self.text_in.setVisible(in_text)
        self.file_in_w.setVisible(not in_text)
        self.text_out.setVisible(in_text)
        self.file_out_w.setVisible(not in_text)
        self.in_fmt_row.setVisible(in_text)
        self.out_fmt_row.setVisible(in_text)

        direction = "ENCRYPT" if is_enc else "DECRYPT"
        self.action_btn.setText(f"RUN AES-{mode.upper()} {direction}")

    # ─── Log ──────────────────────────────────────────────────────────────────
    def log(self, message: str, color: str | None = None, newline: bool = True):
        cur = self.log_text.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color if color else "#333333"))
        cur.setCharFormat(fmt)
        cur.insertText(message + ("\n" if newline else ""))

        self.log_text.setTextCursor(cur)
        self.log_text.ensureCursorVisible()

    # ─── File dialogs ─────────────────────────────────────────────────────────
    def browse_input_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Input File")
        if p:
            self.file_in_entry.setText(p)
            ext = ".enc" if self.rb_encrypt.isChecked() else ".dec"
            self.file_out_entry.setText(p + ext)

    def browse_output_file(self):
        p, _ = QFileDialog.getSaveFileName(self, "Select Output File")
        if p:
            self.file_out_entry.setText(p)

    def browse_kat_file(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "Select KAT JSON File",
            filter="JSON files (*.json);;All files (*.*)"
        )
        if p:
            self.kat_path_entry.setText(p)

    def browse_lib_dll(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "Select Core Library",
            filter="Dynamic Libraries (*.dll *.so *.dylib);;All files (*.*)"
        )
        if p:
            self.lib_path_entry.setText(p)

    def load_custom_dll(self):
        global dll, dll_path
        path = self.lib_path_entry.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.critical(self, "Error", f"Invalid library path:\n{path}")
            return
        try:
            new_dll = ctypes.CDLL(path)
            configure_dll(new_dll)
            dll = new_dll
            dll_path = path
            self.log(f"[OK] Library reloaded: {path}", "#2D6A4F")
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load library:\n{e}")
            self.log(f"[!] Load failed: {e}", "#D62828")

    # ─── KAT ──────────────────────────────────────────────────────────────────
    def execute_kat_test(self):
        if not dll:
            QMessageBox.critical(self, "Error", "Native library is not loaded.")
            return
        path = self.kat_path_entry.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.critical(self, "File Error", f"Invalid path:\n'{path}'")
            return

        # Clean up previous worker safely
        if self.kat_worker is not None:
            if self.kat_worker.isRunning():
                self.kat_worker.wait()
            self.kat_worker.deleteLater()

        self.kat_text.clear()
        self.kat_total_lbl.setText("Total: --")
        self.kat_passed_lbl.setText("Passed: --")
        self.kat_failed_lbl.setText("Failed: --")

        self.kat_worker = KatWorker(path)
        self.kat_worker.progress.connect(self.kat_log)
        self.kat_worker.finished.connect(self.on_kat_finished)

        self.kat_run_btn.setEnabled(False)
        self.kat_stop_btn.setEnabled(True)
        self.kat_worker.start()

    def stop_kat(self):
        if self.kat_worker and self.kat_worker.isRunning():
            self.kat_worker.terminate()
            self.kat_worker.wait()
            self.kat_log("[!] KAT stopped by user")
        self.kat_run_btn.setEnabled(True)
        self.kat_stop_btn.setEnabled(False)

    def on_kat_finished(self, total, passed, failed):
        self.kat_run_btn.setEnabled(True)
        self.kat_stop_btn.setEnabled(False)

        # Safe cleanup: wait for thread exit, then schedule Qt deletion
        worker = self.kat_worker
        self.kat_worker = None
        if worker is not None:
            worker.wait()
            worker.deleteLater()

        self.kat_total_lbl.setText(f"Total: {total}")
        self.kat_passed_lbl.setText(f"Passed: {passed}")
        self.kat_failed_lbl.setText(f"Failed: {failed}")

        if failed == 0 and total > 0:
            self.kat_passed_lbl.setStyleSheet("color: #2D6A4F; font-size: 13px; font-weight: bold;")
            self.kat_failed_lbl.setStyleSheet("color: #2D6A4F; font-size: 13px; font-weight: bold;")
        elif failed > 0:
            self.kat_failed_lbl.setStyleSheet("color: #D62828; font-size: 13px; font-weight: bold;")

    # ─── Benchmark ────────────────────────────────────────────────────────────
    def run_benchmark(self):
        if not dll:
            QMessageBox.critical(self, "Error", "Native library is not loaded.")
            return
        
        build_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build")
        if not os.path.exists(build_dir):
            QMessageBox.critical(self, "Error", f"Build directory not found: {build_dir}")
            return
        
        # Clean up previous worker safely
        if self.bench_worker is not None:
            if self.bench_worker.isRunning():
                self.bench_worker.wait()
            self.bench_worker.deleteLater()
        
        mode = self.bench_mode_combo.currentText()
        size = self.bench_size_combo.currentText()
        threads_text = self.bench_threads_combo.currentText()
        
        if mode == "All Modes":
            mode = None
        if size == "All Sizes":
            size = None
        else:
            size_map = {
                "1 KB": 1024,
                "4 KB": 4096,
                "16 KB": 16384,
                "256 KB": 262144,
                "1 MB": 1048576,
                "8 MB": 8388608
            }
            size = size_map.get(size)
        
        threads = 0 if threads_text == "Auto" else int(threads_text)
        
        self.bench_text.clear()
        self.bench_log("[*] Starting benchmark...")
        
        self.bench_worker = BenchmarkWorker(build_dir, mode, size, threads)
        self.bench_worker.progress.connect(self.bench_log)
        self.bench_worker.finished.connect(self.on_benchmark_finished)
        
        self.bench_btn.setEnabled(False)
        self.bench_stop_btn.setEnabled(True)
        self.bench_worker.start()
    
    def stop_benchmark(self):
        if self.bench_worker and self.bench_worker.isRunning():
            self.bench_worker.terminate()
            self.bench_worker.wait()
            self.bench_log("[!] Benchmark stopped by user")
        self.bench_btn.setEnabled(True)
        self.bench_stop_btn.setEnabled(False)
    
    def on_benchmark_finished(self, results):
        self.bench_btn.setEnabled(True)
        self.bench_stop_btn.setEnabled(False)
        
        # Safe cleanup: wait for thread exit, then schedule Qt deletion
        worker = self.bench_worker
        self.bench_worker = None
        if worker is not None:
            worker.wait()
            worker.deleteLater()
    
    def bench_log(self, message: str, color: str | None = None):
        cur = self.bench_text.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        
        fmt = QTextCharFormat()
        if color:
            fmt.setForeground(QColor(color))
        else:
            if "[ERROR]" in message or "[FAIL" in message:
                fmt.setForeground(QColor("#D62828"))
            elif "[+]" in message or "[SUCCESS]" in message or "Benchmark complete" in message:
                fmt.setForeground(QColor("#2D6A4F"))
            elif "[*]" in message or "===" in message or "---" in message:
                fmt.setForeground(QColor("#00B4D8"))
            elif "[WARNING]" in message:
                fmt.setForeground(QColor("#F4A261"))
            elif "Mean:" in message or "Median:" in message or "Throughput:" in message:
                fmt.setForeground(QColor("#2D6A4F"))
            else:
                fmt.setForeground(QColor("#E76F51"))
        
        cur.setCharFormat(fmt)
        cur.insertText(message + "\n")
        self.bench_text.setTextCursor(cur)
        self.bench_text.ensureCursorVisible()
    
    # ─── Tests ────────────────────────────────────────────────────────────────
    def run_tests(self):
        if not dll:
            QMessageBox.critical(self, "Error", "Native library is not loaded.")
            return
        
        build_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build")
        if not os.path.exists(build_dir):
            QMessageBox.critical(self, "Error", f"Build directory not found: {build_dir}")
            return
        
        # Clean up previous worker safely
        if self.test_worker is not None:
            if self.test_worker.isRunning():
                self.test_worker.wait()
            self.test_worker.deleteLater()
        
        self.test_text.clear()
        self.test_total_lbl.setText("Total: --")
        self.test_passed_lbl.setText("Passed: --")
        self.test_failed_lbl.setText("Failed: --")
        self.test_log("[*] Running Catch2 unit tests...")
        
        self.test_worker = TestWorker(build_dir)
        self.test_worker.progress.connect(self.test_log)
        self.test_worker.finished.connect(self.on_tests_finished)
        
        self.test_btn.setEnabled(False)
        self.test_stop_btn.setEnabled(True)
        self.test_worker.start()
    
    def stop_tests(self):
        if self.test_worker and self.test_worker.isRunning():
            self.test_worker.terminate()
            self.test_worker.wait()
            self.test_log("[!] Tests stopped by user")
        self.test_btn.setEnabled(True)
        self.test_stop_btn.setEnabled(False)
    
    def on_tests_finished(self, total, passed, failed):
        self.test_btn.setEnabled(True)
        self.test_stop_btn.setEnabled(False)
        
        # Safe cleanup: wait for thread exit, then schedule Qt deletion
        worker = self.test_worker
        self.test_worker = None
        if worker is not None:
            worker.wait()
            worker.deleteLater()
        
        self.test_total_lbl.setText(f"Total: {total}")
        self.test_passed_lbl.setText(f"Passed: {passed}")
        self.test_failed_lbl.setText(f"Failed: {failed}")
        
        if failed == 0:
            self.test_passed_lbl.setStyleSheet("color: #2D6A4F; font-size: 13px; font-weight: bold;")
            self.test_failed_lbl.setStyleSheet("color: #2D6A4F; font-size: 13px; font-weight: bold;")
        else:
            self.test_failed_lbl.setStyleSheet("color: #D62828; font-size: 13px; font-weight: bold;")
    
    def test_log(self, message: str, color: str | None = None):
        cur = self.test_text.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        
        fmt = QTextCharFormat()
        if color:
            fmt.setForeground(QColor(color))
        else:
            if "[FAIL]" in message or "FAILED" in message or "[ERROR]" in message:
                fmt.setForeground(QColor("#D62828"))
            elif "[PASS]" in message:
                fmt.setForeground(QColor("#2D6A4F"))
            elif "passed" in message.lower() and "failed" not in message.lower():
                fmt.setForeground(QColor("#2D6A4F"))
            elif "[+]" in message or "[SUCCESS]" in message:
                fmt.setForeground(QColor("#2D6A4F"))
            elif "[*]" in message:
                fmt.setForeground(QColor("#00B4D8"))
            elif "test cases:" in message:
                fmt.setForeground(QColor("#0077B6"))
            else:
                fmt.setForeground(QColor("#6A0572"))
        
        cur.setCharFormat(fmt)
        cur.insertText(message + "\n")
        self.test_text.setTextCursor(cur)
        self.test_text.ensureCursorVisible()
    
    def kat_log(self, message: str, color: str | None = None, newline: bool = True):
        cur = self.kat_text.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        
        fmt = QTextCharFormat()
        if color:
            fmt.setForeground(QColor(color))
        else:
            if "[ERROR]" in message or "FAIL" in message:
                fmt.setForeground(QColor("#D62828"))
            elif "PASS" in message or "[+]" in message:
                fmt.setForeground(QColor("#2D6A4F"))
            elif "[*]" in message or "═" in message:
                fmt.setForeground(QColor("#00B4D8"))
            else:
                fmt.setForeground(QColor("#E76F51"))
        
        cur.setCharFormat(fmt)
        cur.insertText(message + ("\n" if newline else ""))
        self.kat_text.setTextCursor(cur)
        self.kat_text.ensureCursorVisible()

    def _parse(self, text: str, fmt: str) -> bytes:
        if not text:
            return b""
        if fmt == "hex":
            try:
                return bytes.fromhex("".join(text.split()))
            except ValueError:
                raise ValueError("Invalid hex string.")
        return text.encode()

    # ─── Execute Crypto ───────────────────────────────────────────────────────
    def execute_crypto(self):
        if not dll:
            QMessageBox.critical(self, "Error", "Native library not loaded.")
            return

        mode      = self.mode_combo.currentText()
        direction = "encrypt" if self.rb_encrypt.isChecked() else "decrypt"
        in_text   = self.rb_in_text.isChecked()
        is_aead   = 1 if mode in ("gcm", "ccm") else 0
        allow_ecb = 1 if self.allow_ecb_check.isChecked() else 0

        self.log(f"[*] {direction.upper()} AES-{mode.upper()} \u2026", "#00B4D8")

        # ECB warning
        if mode == "ecb" and direction == "encrypt":
            self.log("[!] WARNING: ECB mode is insecure \u2014 identical blocks produce identical ciphertext.", "#D62828")

        try:
            key_bytes = self._parse(self.key_entry.text(), self.key_format_combo.currentText())
        except ValueError as e:
            QMessageBox.critical(self, "Key Error", str(e)); return

        try:
            iv_bytes = self._parse(self.iv_entry.text(), "hex")
        except ValueError as e:
            QMessageBox.critical(self, "IV Error", str(e)); return

        # Auto-generate key/IV when empty (encrypt only)
        if direction == "encrypt":
            if not key_bytes:
                key_bytes = secrets.token_bytes(32)  # AES-256
                self.key_entry.setText(key_bytes.hex().upper())
                self.key_format_combo.setCurrentText("hex")
                self.log("[+] Auto-generated key (256-bit)", "#2D6A4F")
            if not iv_bytes and mode != "ecb":
                iv_len = 12 if mode in ("gcm", "ccm") else 16
                iv_bytes = secrets.token_bytes(iv_len)
                self.iv_entry.setText(iv_bytes.hex().upper())
                self.log(f"[+] Auto-generated IV ({iv_len * 8}-bit)", "#2D6A4F")
        else:
            # Decrypt requires key and IV
            if not key_bytes:
                QMessageBox.critical(self, "Key Required", "Decryption needs a key!"); return
            if mode != "ecb" and not iv_bytes:
                QMessageBox.critical(self, "IV Required", f"AES-{mode.upper()} decrypt needs IV!"); return

        aad_str = self.aad_entry.text() if is_aead else ""

        # Input bytes
        input_bytes = b""
        if in_text:
            raw = self.text_in.toPlainText().rstrip("\n")
            if not raw:
                QMessageBox.critical(self, "Input Error", "Provide input data."); return
            in_fmt = self.input_format_combo.currentText()
            # Warn if decrypting with text format (ciphertext is usually hex/base64)
            if direction == "decrypt" and in_fmt == "text":
                QMessageBox.warning(self, "Input Format",
                    "Input format is 'text' but you are decrypting.\n"
                    "Ciphertext should usually be 'hex' or 'base64'.\n"
                    "Switch format if decryption fails.")
            try:
                if in_fmt == "hex":
                    input_bytes = bytes.fromhex("".join(raw.split()))
                elif in_fmt == "base64":
                    input_bytes = base64.b64decode(raw)
                else:  # "text"
                    input_bytes = raw.encode('utf-8')
            except Exception as e:
                QMessageBox.critical(self, "Decode Error", f"Failed to decode input as {in_fmt}: {e}"); return
        else:
            fpath = self.file_in_entry.text().strip()
            if not fpath or not os.path.exists(fpath):
                QMessageBox.critical(self, "File Error", "Invalid input file."); return
            try:
                with open(fpath, "rb") as f:
                    input_bytes = f.read()
            except Exception as e:
                QMessageBox.critical(self, "File Error", str(e)); return

        # Allocate buffers (XTS doubles the size, so use 2*n + 256 for safety)
        n           = len(input_bytes)
        out_cap     = 2 * n + 256
        out_buf     = (c_ubyte * out_cap)()
        out_len     = c_int(out_cap)          # DLL uses this as buffer capacity
        key_cap     = 64
        key_out     = (c_ubyte * key_cap)()
        key_out_len = c_int(key_cap)           # DLL uses this as buffer capacity
        iv_cap      = 16
        iv_out      = (c_ubyte * iv_cap)()
        iv_out_len  = c_int(iv_cap)            # DLL uses this as buffer capacity
        tag_cap     = 16
        tag_out     = (c_ubyte * tag_cap)()
        tag_out_len = c_int(tag_cap)           # DLL uses this as buffer capacity
        errbuf      = ctypes.create_string_buffer(256)
        in_buf      = (c_ubyte * n).from_buffer_copy(input_bytes)

        k_buf = (c_ubyte * len(key_bytes)).from_buffer_copy(key_bytes) if key_bytes else None
        k_len = len(key_bytes)
        i_buf = (c_ubyte * len(iv_bytes)).from_buffer_copy(iv_bytes)  if iv_bytes  else None
        i_len = len(iv_bytes)

        if direction == "encrypt":
            res = dll.encrypt_aes_c(
                mode.encode(), in_buf, n,
                k_buf, k_len, i_buf, i_len,
                aad_str.encode() if aad_str else None,
                is_aead, allow_ecb,
                out_buf, byref(out_len),
                key_out, byref(key_out_len),
                iv_out,  byref(iv_out_len),
                tag_out, byref(tag_out_len),
                errbuf
            )
        else:
            # Tag for AEAD decrypt
            tag_bytes = b""
            if is_aead:
                ts = self.tag_entry.text().strip()
                if not ts:
                    QMessageBox.critical(self, "Tag Required", "AEAD decrypt requires tag!"); return
                try:
                    tag_bytes = bytes.fromhex(ts)
                except ValueError:
                    QMessageBox.critical(self, "Tag Error", "Tag must be hex."); return

            t_buf = (c_ubyte * len(tag_bytes)).from_buffer_copy(tag_bytes) if tag_bytes else None
            t_len = len(tag_bytes)
            res = dll.decrypt_aes_c(
                mode.encode(), in_buf, n,
                k_buf, k_len, i_buf, i_len,
                aad_str.encode() if aad_str else None,
                t_buf, t_len, is_aead,
                out_buf, byref(out_len), errbuf
            )

        if res != 0:
            err = errbuf.value.decode(errors="ignore")
            self.log(f"[ERROR] Code {res}: {err}", "#D62828")
            QMessageBox.critical(self, "Crypto Error", err)
            return

        self.log("[+] Operation successful!", "#2D6A4F")

        # Show used key/iv/tag after encrypt
        if direction == "encrypt":
            uk = bytes(key_out[:key_out_len.value]) if key_out_len.value else key_bytes
            ui = bytes(iv_out[:iv_out_len.value])   if iv_out_len.value  else iv_bytes
            ut = bytes(tag_out[:tag_out_len.value]) if tag_out_len.value else b""
            self.key_entry.setText(uk.hex().upper())
            self.log(f"[+] Key : {uk.hex().upper()}", "#2D6A4F")
            if ui:
                self.iv_entry.setText(ui.hex().upper())
                self.log(f"[+] IV  : {ui.hex().upper()}", "#2D6A4F")
            if is_aead and ut:
                self.tag_entry.setText(ut.hex().upper())
                self.log(f"[+] Tag : {ut.hex().upper()}", "#2D6A4F")

        result = bytes(out_buf[:out_len.value])

        if in_text:
            out_fmt = self.output_format_combo.currentText()
            if out_fmt == "hex":
                txt = result.hex().upper()
            elif out_fmt == "base64":
                txt = base64.b64encode(result).decode('utf-8')
            else:  # "raw"
                txt = result.decode('utf-8', errors="replace")
            self.text_out.setPlainText(txt)
            self.log(f"[+] Output: {len(result)} bytes → {out_fmt}", "#2D6A4F")
        else:
            out_path = self.file_out_entry.text().strip()
            if not out_path:
                out_path, _ = QFileDialog.getSaveFileName(self, "Save Output As")
                if not out_path:
                    self.log("[!] Save cancelled.", "#D62828"); return
                self.file_out_entry.setText(out_path)
            try:
                with open(out_path, "wb") as f:
                    f.write(result)
                self.log(f"[+] Saved {len(result):,} bytes → {out_path}", "#2D6A4F")

                if direction == "encrypt":
                    uk  = bytes(key_out[:key_out_len.value]) if key_out_len.value else key_bytes
                    ui  = bytes(iv_out[:iv_out_len.value])   if iv_out_len.value  else iv_bytes
                    ut  = bytes(tag_out[:tag_out_len.value]) if tag_out_len.value else b""
                    key_bits = len(uk) * 8
                    meta = {
                        "alg":  f"AES-{key_bits}-{mode.upper()}",
                        "mode": mode,
                        "iv":   ui.hex().upper(),
                        "aad":  aad_str,
                        "tag":  ut.hex().upper() if is_aead else "",
                    }
                    sidecar = out_path + ".json"
                    with open(sidecar, "w") as sf:
                        json.dump(meta, sf, indent=2)
                    self.log(f"[+] Metadata → {sidecar}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", str(e))
                self.log(f"[!] {e}", "#D62828")


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    app.setFont(QFont("Segoe UI", 12))
    win = CryptoApp()
    win.show()
    sys.exit(app.exec())
