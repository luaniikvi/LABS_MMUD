#!/usr/bin/env python3
"""Lab 4 — Hashing, PKI, and Practical Attacks — PyQt6 GUI"""

import ctypes
import ctypes.util
import json
import os
import subprocess
import sys

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSpinBox, QTabWidget, QTextEdit, QVBoxLayout,
    QWidget, QCheckBox, QMessageBox, QSizePolicy
)


# ============================================================================
# DLL Wrapper
# ============================================================================

class HashEngine:
    def __init__(self, dll_path):
        dll_dir = os.path.dirname(os.path.abspath(dll_path))
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if hasattr(os, 'add_dll_directory'):
            os.add_dll_directory(dll_dir)
            os.add_dll_directory(script_dir)
        os.environ['PATH'] = dll_dir + os.pathsep + script_dir + os.pathsep + os.environ.get('PATH', '')
        self.dll = ctypes.CDLL(dll_path)

        # lab4_hash
        self.dll.lab4_hash.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int,
            ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_hash.restype = ctypes.c_int

        # lab4_hash_file
        self.dll.lab4_hash_file.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
            ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_hash_file.restype = ctypes.c_int

        # lab4_shake
        self.dll.lab4_shake.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int,
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_shake.restype = ctypes.c_int

        # lab4_shake_file
        self.dll.lab4_shake_file.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_shake_file.restype = ctypes.c_int

        # lab4_hmac
        self.dll.lab4_hmac.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_int,
            ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_hmac.restype = ctypes.c_int

        # lab4_hmac_file
        self.dll.lab4_hmac_file.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int,
            ctypes.c_char_p, ctypes.c_int,
            ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_hmac_file.restype = ctypes.c_int

        # lab4_parse_x509
        self.dll.lab4_parse_x509.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_parse_x509.restype = ctypes.c_int

        # lab4_length_ext
        self.dll.lab4_length_ext.argtypes = [
            ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_length_ext.restype = ctypes.c_int

        # lab4_md5_demo
        self.dll.lab4_md5_demo.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        self.dll.lab4_md5_demo.restype = ctypes.c_int

    def hash_text(self, algo, text):
        data = text.encode('utf-8')
        buf = ctypes.create_string_buffer(512)
        err = ctypes.create_string_buffer(1024)
        arr = (ctypes.c_uint8 * len(data))(*data)
        rc = self.dll.lab4_hash(algo.encode(), arr, len(data), buf, 512, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return buf.value.decode()

    def hash_file(self, algo, filepath, stream=False):
        buf = ctypes.create_string_buffer(512)
        err = ctypes.create_string_buffer(1024)
        rc = self.dll.lab4_hash_file(algo.encode(), filepath.encode(), 1 if stream else 0, buf, 512, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return buf.value.decode()

    def shake(self, algo, text, outlen):
        data = text.encode('utf-8')
        buf = ctypes.create_string_buffer(512)
        err = ctypes.create_string_buffer(1024)
        arr = (ctypes.c_uint8 * len(data))(*data)
        rc = self.dll.lab4_shake(algo.encode(), arr, len(data), outlen, buf, 512, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return buf.value.decode()

    def shake_file(self, algo, filepath, outlen, stream=False):
        buf = ctypes.create_string_buffer(512)
        err = ctypes.create_string_buffer(1024)
        rc = self.dll.lab4_shake_file(algo.encode(), filepath.encode(), 1 if stream else 0, outlen, buf, 512, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return buf.value.decode()

    def hmac(self, algo, key_hex, text):
        key = bytes.fromhex(key_hex)
        data = text.encode('utf-8')
        buf = ctypes.create_string_buffer(512)
        err = ctypes.create_string_buffer(1024)
        karr = (ctypes.c_uint8 * len(key))(*key)
        darr = (ctypes.c_uint8 * len(data))(*data)
        rc = self.dll.lab4_hmac(algo.encode(), karr, len(key), darr, len(data), buf, 512, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return buf.value.decode()

    def hmac_file(self, algo, key_hex, filepath, stream=False):
        key = bytes.fromhex(key_hex)
        buf = ctypes.create_string_buffer(512)
        err = ctypes.create_string_buffer(1024)
        karr = (ctypes.c_uint8 * len(key))(*key)
        rc = self.dll.lab4_hmac_file(algo.encode(), karr, len(key), filepath.encode(), 1 if stream else 0, buf, 512, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return buf.value.decode()

    def parse_x509(self, cert_path):
        buf = ctypes.create_string_buffer(65536)
        err = ctypes.create_string_buffer(1024)
        rc = self.dll.lab4_parse_x509(cert_path.encode(), buf, 65536, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return json.loads(buf.value.decode())

    def length_ext(self, mac_hex, key_len, msg_len, append_data):
        buf = ctypes.create_string_buffer(65536)
        err = ctypes.create_string_buffer(1024)
        rc = self.dll.lab4_length_ext(mac_hex.encode(), key_len, msg_len,
                                       append_data.encode(), buf, 65536, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return json.loads(buf.value.decode())

    def md5_demo(self, dir_path):
        buf = ctypes.create_string_buffer(65536)
        err = ctypes.create_string_buffer(1024)
        rc = self.dll.lab4_md5_demo(dir_path.encode(), buf, 65536, err, 1024)
        if rc != 0:
            raise RuntimeError(err.value.decode('utf-8', errors='replace'))
        return json.loads(buf.value.decode())


# ============================================================================
# Subprocess Worker (for benchmark/tests/kat)
# ============================================================================

class SubprocessWorker(QThread):
    output_line = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, cmd, cwd=None):
        super().__init__()
        self.cmd = cmd
        self.cwd = cwd
        self._proc = None

    def run(self):
        try:
            self._proc = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=self.cwd
            )
            for line in self._proc.stdout:
                self.output_line.emit(line.rstrip('\n'))
            self._proc.wait()
        except Exception as e:
            self.output_line.emit(f"[ERROR] {e}")
        finally:
            self.finished.emit()

    def stop(self):
        if self._proc:
            self._proc.terminate()


# ============================================================================
# Main GUI
# ============================================================================

class Lab4GUI(QWidget):
    def __init__(self):
        super().__init__()
        self.engine = None
        self._build_dir = ""
        self._worker = None
        self.setWindowTitle("Lab 4 — Hashing, PKI, and Practical Attacks")
        self.setMinimumSize(820, 620)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        layout = QVBoxLayout(self)
        layout.setSizeConstraint(layout.SizeConstraint.SetDefaultConstraint)

        # DLL selector
        dll_group = QGroupBox("Select DLL Library (hashtool.dll)")
        dll_layout = QHBoxLayout(dll_group)
        self.dll_path = QLineEdit()
        self.dll_path.setPlaceholderText("hashtool.dll")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.load_dll)
        dll_layout.addWidget(self.dll_path)
        dll_layout.addWidget(browse_btn)
        layout.addWidget(dll_group)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.tabs.addTab(self.create_hash_tab(), "Hash")
        self.tabs.addTab(self.create_hmac_tab(), "HMAC")
        self.tabs.addTab(self.create_shake_tab(), "SHAKE")
        self.tabs.addTab(self.create_x509_tab(), "X.509 Inspector")
        self.tabs.addTab(self.create_md5_tab(), "MD5 Collision")
        self.tabs.addTab(self.create_lext_tab(), "Length-Extension")
        self.tabs.addTab(self.create_benchmark_tab(), "Benchmark")
        self.tabs.addTab(self.create_catch2_tab(), "Catch2 Tests")
        self.tabs.addTab(self.create_kat_tab(), "KAT Tests")
        layout.addWidget(self.tabs)

        # Allow tab area to expand above the status bar
        layout.addStretch()

        # Status bar
        self.status = QLabel("Ready — load DLL to start")
        layout.addWidget(self.status)

    def _enable_buttons(self):
        self.hash_btn.setEnabled(True)
        self.hmac_btn.setEnabled(True)
        self.shake_btn.setEnabled(True)
        self.x509_btn.setEnabled(True)
        self.md5_btn.setEnabled(True)
        self.lext_btn.setEnabled(True)

    def _mono_font(self):
        return QFont("Consolas", 9)

    def _set_status(self, msg, color="black"):
        self.status.setText(msg)
        self.status.setStyleSheet(f"color: {color};")

    # ---- DLL loading ----
    def load_dll(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select DLL", "", "DLL (*.dll);;All (*)")
        if not path:
            return
        self.dll_path.setText(path)
        try:
            self.engine = HashEngine(path)
            dll_dir = os.path.dirname(os.path.abspath(path))
            self._build_dir = dll_dir
            self._set_status(f"DLL loaded — build dir: {dll_dir}", "green")
            self._enable_buttons()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load DLL: {e}")

    def _get_exe_path(self, name):
        build_dir = self._build_dir
        if not build_dir:
            QMessageBox.warning(self, "Error", "Please load the DLL first.")
            return None
        for ext in ['.exe', '']:
            p = os.path.join(build_dir, name + ext)
            if os.path.exists(p):
                return p
        QMessageBox.warning(self, "Error", f"Executable not found: {name} in {build_dir}")
        return None

    def _run_subprocess(self, cmd, output_widget, run_btn, stop_btn):
        if self._worker:
            return
        output_widget.clear()
        run_btn.setEnabled(False)
        stop_btn.setEnabled(True)
        self._worker = SubprocessWorker(cmd, cwd=self._build_dir or None)
        self._worker.output_line.connect(lambda line: output_widget.append(line))
        self._worker.finished.connect(lambda: self._on_worker_done(run_btn, stop_btn))
        self._worker.start()

    def _on_worker_done(self, run_btn, stop_btn):
        run_btn.setEnabled(True)
        stop_btn.setEnabled(False)
        self._worker = None
        self._set_status("Done", "green")

    def stop_worker(self):
        if self._worker:
            self._worker.stop()

    # ================================================================
    # Hash Tab
    # ================================================================
    def create_hash_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)

        algo_l = QHBoxLayout()
        algo_l.addWidget(QLabel("Algorithm:"))
        self.hash_algo = QComboBox()
        self.hash_algo.addItems(["sha256", "sha224", "sha384", "sha512",
                                  "sha3-256", "sha3-224", "sha3-384", "sha3-512", "md5"])
        algo_l.addWidget(self.hash_algo); algo_l.addStretch()
        layout.addLayout(algo_l)

        mode_l = QHBoxLayout()
        mode_l.addWidget(QLabel("Input Mode:"))
        self.hash_mode_combo = QComboBox()
        self.hash_mode_combo.addItems(["Text", "File"])
        self.hash_mode_combo.currentTextChanged.connect(self._on_hash_mode_changed)
        mode_l.addWidget(self.hash_mode_combo); mode_l.addStretch()
        layout.addLayout(mode_l)

        self.hash_text_input = QTextEdit()
        self.hash_text_input.setPlaceholderText("Enter text to hash...")
        layout.addWidget(QLabel("Input Text:"))
        layout.addWidget(self.hash_text_input)

        self.hash_file_container = QWidget()
        file_layout = QVBoxLayout(self.hash_file_container)
        file_layout.setContentsMargins(0, 0, 0, 0)
        file_l = QHBoxLayout()
        self.hash_file_edit = QLineEdit(); self.hash_file_edit.setPlaceholderText("Or select file...")
        fb = QPushButton("Browse..."); fb.clicked.connect(self.browse_hash_file)
        file_l.addWidget(self.hash_file_edit); file_l.addWidget(fb)
        file_layout.addLayout(file_l)
        self.hash_stream_cb = QCheckBox("Stream mode (large files)")
        file_layout.addWidget(self.hash_stream_cb)
        layout.addWidget(self.hash_file_container)

        self.hash_file_container.setVisible(False)

        self.hash_btn = QPushButton("Compute Hash"); self.hash_btn.clicked.connect(self.do_hash)
        self.hash_btn.setEnabled(False); layout.addWidget(self.hash_btn)

        self.hash_output = QTextEdit(); self.hash_output.setReadOnly(True)
        self.hash_output.setFont(self._mono_font())
        self.hash_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Result:")); layout.addWidget(self.hash_output)
        layout.addStretch()
        return tab

    def _on_hash_mode_changed(self, mode):
        if mode == "Text":
            self.hash_text_input.setVisible(True)
            self.hash_file_container.setVisible(False)
        else:
            self.hash_text_input.setVisible(False)
            self.hash_file_container.setVisible(True)

    def browse_hash_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path: self.hash_file_edit.setText(path)

    def do_hash(self):
        if not self.engine: return
        algo = self.hash_algo.currentText()
        try:
            mode = self.hash_mode_combo.currentText()
            if mode == "File":
                filepath = self.hash_file_edit.text()
                if not filepath or not os.path.isfile(filepath):
                    raise RuntimeError("Please select a valid file")
                result = self.engine.hash_file(algo, filepath, self.hash_stream_cb.isChecked())
            else:
                text = self.hash_text_input.toPlainText()
                result = self.engine.hash_text(algo, text)
            self.hash_output.setText(f"{algo.upper()}: {result}")
            self._set_status("Hash computed", "green")
        except Exception as e:
            self.hash_output.setText(f"[ERROR] {e}")

    # ================================================================
    # HMAC Tab
    # ================================================================
    def create_hmac_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        algo_l = QHBoxLayout()
        algo_l.addWidget(QLabel("Algorithm:"))
        self.hmac_algo = QComboBox()
        self.hmac_algo.addItems(["sha256", "sha224", "sha384", "sha512"])
        algo_l.addWidget(self.hmac_algo); algo_l.addStretch()
        layout.addLayout(algo_l)

        self.hmac_key = QLineEdit(); self.hmac_key.setPlaceholderText("Key (hex, e.g. AABB0011...)")
        layout.addWidget(QLabel("Key (hex):")); layout.addWidget(self.hmac_key)

        mode_l = QHBoxLayout()
        mode_l.addWidget(QLabel("Input Mode:"))
        self.hmac_mode = QComboBox(); self.hmac_mode.addItems(["Text", "File"])
        self.hmac_mode.currentTextChanged.connect(self._on_hmac_mode_changed)
        mode_l.addWidget(self.hmac_mode); mode_l.addStretch()
        layout.addLayout(mode_l)

        self.hmac_text = QTextEdit()
        self.hmac_text.setPlaceholderText("Enter message...")
        self.hmac_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Message:")); layout.addWidget(self.hmac_text)

        self.hmac_file_row = QWidget()
        frow = QHBoxLayout(self.hmac_file_row)
        frow.setContentsMargins(0,0,0,0)
        self.hmac_file = QLineEdit(); self.hmac_file.setPlaceholderText("Input file path...")
        cb = QPushButton("Browse..."); cb.clicked.connect(lambda: self._browse_to(self.hmac_file))
        frow.addWidget(self.hmac_file); frow.addWidget(cb)
        layout.addWidget(self.hmac_file_row)
        self.hmac_file_row.hide()

        self.hmac_btn = QPushButton("Compute HMAC"); self.hmac_btn.clicked.connect(self.do_hmac)
        self.hmac_btn.setEnabled(False); layout.addWidget(self.hmac_btn)

        self.hmac_output = QTextEdit(); self.hmac_output.setReadOnly(True)
        self.hmac_output.setFont(self._mono_font())
        self.hmac_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Result:")); layout.addWidget(self.hmac_output)
        layout.addStretch()
        return tab

    def do_hmac(self):
        if not self.engine: return
        try:
            mode = self.hmac_mode.currentText()
            if mode == "Text":
                result = self.engine.hmac(self.hmac_algo.currentText(),
                                          self.hmac_key.text(),
                                          self.hmac_text.toPlainText())
            else:
                path = self.hmac_file.text()
                if not path:
                    raise RuntimeError("Please select an input file.")
                result = self.engine.hmac_file(self.hmac_algo.currentText(),
                                               self.hmac_key.text(),
                                               path,
                                               stream=False)
            self.hmac_output.setText(f"HMAC-{self.hmac_algo.currentText().upper()}: {result}")
        except Exception as e:
            self.hmac_output.setText(f"[ERROR] {e}")

    def _on_hmac_mode_changed(self, mode):
        is_text = mode == "Text"
        self.hmac_text.setVisible(is_text)
        self.hmac_file_row.setVisible(not is_text)

    # ================================================================
    # SHAKE Tab
    # ================================================================
    def create_shake_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        opt = QHBoxLayout()
        opt.addWidget(QLabel("Algorithm:"))
        self.shake_algo = QComboBox(); self.shake_algo.addItems(["shake128", "shake256"])
        opt.addWidget(self.shake_algo)
        opt.addWidget(QLabel("Output (bytes):"))
        self.shake_outlen = QSpinBox(); self.shake_outlen.setRange(1, 1024); self.shake_outlen.setValue(64)
        opt.addWidget(self.shake_outlen); opt.addStretch()
        layout.addLayout(opt)

        mode_l = QHBoxLayout()
        mode_l.addWidget(QLabel("Input Mode:"))
        self.shake_mode = QComboBox(); self.shake_mode.addItems(["Text", "File"])
        self.shake_mode.currentTextChanged.connect(self._on_shake_mode_changed)
        mode_l.addWidget(self.shake_mode); mode_l.addStretch()
        layout.addLayout(mode_l)

        self.shake_text = QTextEdit()
        self.shake_text.setPlaceholderText("Enter text...")
        self.shake_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Input:")); layout.addWidget(self.shake_text)

        self.shake_file_row = QWidget()
        frow = QHBoxLayout(self.shake_file_row)
        frow.setContentsMargins(0,0,0,0)
        self.shake_file = QLineEdit(); self.shake_file.setPlaceholderText("Input file path...")
        cb = QPushButton("Browse..."); cb.clicked.connect(lambda: self._browse_to(self.shake_file))
        frow.addWidget(self.shake_file); frow.addWidget(cb)
        layout.addWidget(self.shake_file_row)
        self.shake_file_row.hide()

        self.shake_btn = QPushButton("Compute SHAKE"); self.shake_btn.clicked.connect(self.do_shake)
        self.shake_btn.setEnabled(False); layout.addWidget(self.shake_btn)

        self.shake_output = QTextEdit(); self.shake_output.setReadOnly(True)
        self.shake_output.setFont(self._mono_font())
        self.shake_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Result:")); layout.addWidget(self.shake_output)
        layout.addStretch()
        return tab

    def _on_shake_mode_changed(self, mode):
        is_text = mode == "Text"
        self.shake_text.setVisible(is_text)
        self.shake_file_row.setVisible(not is_text)

    def do_shake(self):
        if not self.engine: return
        try:
            mode = self.shake_mode.currentText()
            outlen = self.shake_outlen.value()
            if mode == "Text":
                result = self.engine.shake(self.shake_algo.currentText(), self.shake_text.toPlainText(), outlen)
            else:
                path = self.shake_file.text()
                if not path:
                    raise RuntimeError("Please select an input file.")
                result = self.engine.shake_file(self.shake_algo.currentText(), path, outlen, stream=False)
            self.shake_output.setText(f"{self.shake_algo.currentText().upper()} ({outlen} bytes): {result}")
        except Exception as e:
            self.shake_output.setText(f"[ERROR] {e}")

    # ================================================================
    # X.509 Tab
    # ================================================================
    def create_x509_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        cert_l = QHBoxLayout()
        self.x509_cert = QLineEdit(); self.x509_cert.setPlaceholderText("Certificate PEM file...")
        cb = QPushButton("Browse..."); cb.clicked.connect(lambda: self._browse_to(self.x509_cert))
        cert_l.addWidget(self.x509_cert); cert_l.addWidget(cb)
        layout.addWidget(QLabel("Certificate:")); layout.addLayout(cert_l)

        self.x509_btn = QPushButton("Parse Certificate"); self.x509_btn.clicked.connect(self.do_x509)
        self.x509_btn.setEnabled(False); layout.addWidget(self.x509_btn)

        self.x509_output = QTextEdit(); self.x509_output.setReadOnly(True)
        self.x509_output.setFont(self._mono_font())
        self.x509_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Certificate Info:")); layout.addWidget(self.x509_output)
        layout.addStretch()
        return tab

    def _browse_to(self, line_edit):
        path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "PEM (*.pem);;All (*)")
        if path: line_edit.setText(path)

    def do_x509(self):
        if not self.engine: return
        try:
            info = self.engine.parse_x509(self.x509_cert.text())
            lines = []
            lines.append(f"Version:     v{info.get('version', '?')}")
            lines.append(f"Subject:     {info.get('subject', '')}")
            lines.append(f"Issuer:      {info.get('issuer', '')}")
            lines.append(f"Serial:      {info.get('serial_number', '')}")
            lines.append(f"Public Key:  {info.get('public_key_algo', '')} ({info.get('public_key_params', '')})")
            lines.append(f"Sig Algo:    {info.get('signature_algo', '')}")
            lines.append(f"Not Before:  {info.get('not_before', '')}")
            lines.append(f"Not After:   {info.get('not_after', '')}")
            lines.append(f"Fingerprint: {info.get('fingerprint_sha256', '')}")
            ku = info.get('key_usage', [])
            if ku: lines.append(f"Key Usage:   {', '.join(ku)}")
            san = info.get('san_entries', [])
            if san: lines.append(f"SANs:        {', '.join(san)}")
            self.x509_output.setText('\n'.join(lines))
        except Exception as e:
            self.x509_output.setText(f"[ERROR] {e}")

    # ================================================================
    # MD5 Collision Tab
    # ================================================================
    def create_md5_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        dir_l = QHBoxLayout()
        self.md5_dir = QLineEdit()
        self.md5_dir.setPlaceholderText("demo/md5_collision (auto-detected)")
        db = QPushButton("Browse..."); db.clicked.connect(lambda: self._browse_dir(self.md5_dir))
        dir_l.addWidget(self.md5_dir); dir_l.addWidget(db)
        layout.addWidget(QLabel("Collision directory:")); layout.addLayout(dir_l)

        self.md5_btn = QPushButton("Run MD5 Demo"); self.md5_btn.clicked.connect(self.do_md5)
        self.md5_btn.setEnabled(False); layout.addWidget(self.md5_btn)

        self.md5_output = QTextEdit(); self.md5_output.setReadOnly(True)
        self.md5_output.setFont(self._mono_font())
        self.md5_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Result:")); layout.addWidget(self.md5_output)
        layout.addStretch()
        return tab

    def _browse_dir(self, line_edit):
        d = QFileDialog.getExistingDirectory(self, "Select Directory")
        if d: line_edit.setText(d)

    def do_md5(self):
        if not self.engine: return
        d = self.md5_dir.text()
        if not d:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            d = os.path.join(script_dir, "demo", "md5_collision")
        try:
            result = self.engine.md5_demo(d)
            lines = ["MD5 Collision Demonstration", "=" * 40]
            for fkey in ["file_a", "file_b"]:
                f = result[fkey]
                lines.append(f"\n{fkey.upper()}: {f['path']} ({f['size']} bytes)")
                lines.append(f"  MD5:    {f['md5']}")
                lines.append(f"  SHA256: {f['sha256']}")
            lines.append(f"\nMD5 Match:    {'YES (COLLISION!)' if result['md5_match'] else 'NO'}")
            lines.append(f"SHA256 Match: {'YES' if result['sha256_match'] else 'NO (different)'}")
            self.md5_output.setText('\n'.join(lines))
        except Exception as e:
            self.md5_output.setText(f"[ERROR] {e}")

    # ================================================================
    # Length-Extension Tab
    # ================================================================
    def create_lext_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        self.lext_mac = QLineEdit(); self.lext_mac.setPlaceholderText("Original MAC (hex)")
        layout.addWidget(QLabel("Original MAC:")); layout.addWidget(self.lext_mac)

        params = QHBoxLayout()
        params.addWidget(QLabel("Key Length:"))
        self.lext_keylen = QSpinBox(); self.lext_keylen.setRange(1, 256); self.lext_keylen.setValue(14)
        params.addWidget(self.lext_keylen)
        params.addWidget(QLabel("Msg Length:"))
        self.lext_msglen = QSpinBox(); self.lext_msglen.setRange(1, 65536); self.lext_msglen.setValue(5)
        params.addWidget(self.lext_msglen)
        params.addStretch()
        layout.addLayout(params)

        self.lext_append = QLineEdit(); self.lext_append.setPlaceholderText("Data to append (e.g. &admin=1)")
        layout.addWidget(QLabel("Append Data:")); layout.addWidget(self.lext_append)

        self.lext_btn = QPushButton("Execute Attack"); self.lext_btn.clicked.connect(self.do_lext)
        self.lext_btn.setEnabled(False); layout.addWidget(self.lext_btn)

        self.lext_output = QTextEdit(); self.lext_output.setReadOnly(True)
        self.lext_output.setFont(self._mono_font())
        self.lext_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Result:")); layout.addWidget(self.lext_output)
        layout.addStretch()
        return tab

    def do_lext(self):
        if not self.engine: return
        try:
            result = self.engine.length_ext(
                self.lext_mac.text(), self.lext_keylen.value(),
                self.lext_msglen.value(), self.lext_append.text())
            lines = ["Length-Extension Attack Result", "=" * 40]
            lines.append(f"Forged MAC:       {result['forged_mac']}")
            lines.append(f"Forged Message:   {result['forged_message_hex']}")
            lines.append(f"Padding (hex):    {result['padding_hex']}")
            self.lext_output.setText('\n'.join(lines))
        except Exception as e:
            self.lext_output.setText(f"[ERROR] {e}")

    # ================================================================
    # Benchmark Tab
    # ================================================================
    def create_benchmark_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        btn_l = QHBoxLayout()
        self.bm_run_btn = QPushButton("Run Benchmark"); self.bm_run_btn.clicked.connect(self.do_benchmark)
        self.bm_stop_btn = QPushButton("Stop"); self.bm_stop_btn.clicked.connect(self.stop_worker)
        self.bm_stop_btn.setEnabled(False)
        btn_l.addWidget(self.bm_run_btn); btn_l.addWidget(self.bm_stop_btn); btn_l.addStretch()
        layout.addLayout(btn_l)
        self.bm_output = QTextEdit(); self.bm_output.setReadOnly(True); self.bm_output.setFont(self._mono_font())
        self.bm_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Output:")); layout.addWidget(self.bm_output)
        layout.addStretch()
        return tab

    def do_benchmark(self):
        exe = self._get_exe_path("benchmark")
        if not exe: return
        self._set_status("Running benchmark...", "orange")
        self._run_subprocess([exe, "--verbose"], self.bm_output, self.bm_run_btn, self.bm_stop_btn)

    # ================================================================
    # Catch2 Tab
    # ================================================================
    def create_catch2_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        btn_l = QHBoxLayout()
        self.ct_run_btn = QPushButton("Run Tests"); self.ct_run_btn.clicked.connect(self.do_catch2)
        self.ct_stop_btn = QPushButton("Stop"); self.ct_stop_btn.clicked.connect(self.stop_worker)
        self.ct_stop_btn.setEnabled(False)
        btn_l.addWidget(self.ct_run_btn); btn_l.addWidget(self.ct_stop_btn); btn_l.addStretch()
        layout.addLayout(btn_l)
        self.ct_output = QTextEdit(); self.ct_output.setReadOnly(True); self.ct_output.setFont(self._mono_font())
        self.ct_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Output:")); layout.addWidget(self.ct_output)
        layout.addStretch()
        return tab

    def do_catch2(self):
        exe = self._get_exe_path("catch2_test")
        if not exe: return
        self._set_status("Running Catch2 tests...", "orange")
        self._run_subprocess([exe, "--reporter", "console"], self.ct_output, self.ct_run_btn, self.ct_stop_btn)

    # ================================================================
    # KAT Tab
    # ================================================================
    def create_kat_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        opt = QHBoxLayout()
        opt.addWidget(QLabel("KAT File:"))
        self.kat_combo = QComboBox()
        self.kat_combo.addItems(["sha2_kats.json", "sha3_kats.json", "md5_kats.json"])
        opt.addWidget(self.kat_combo); opt.addStretch()
        layout.addLayout(opt)

        btn_l = QHBoxLayout()
        self.kat_run_btn = QPushButton("Run KAT"); self.kat_run_btn.clicked.connect(self.do_kat)
        self.kat_stop_btn = QPushButton("Stop"); self.kat_stop_btn.clicked.connect(self.stop_worker)
        self.kat_stop_btn.setEnabled(False)
        btn_l.addWidget(self.kat_run_btn); btn_l.addWidget(self.kat_stop_btn); btn_l.addStretch()
        layout.addLayout(btn_l)

        self.kat_output = QTextEdit(); self.kat_output.setReadOnly(True); self.kat_output.setFont(self._mono_font())
        self.kat_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(QLabel("Output:")); layout.addWidget(self.kat_output)
        layout.addStretch()
        return tab

    def do_kat(self):
        exe = self._get_exe_path("hashtool")
        if not exe: return
        script_dir = os.path.dirname(os.path.abspath(__file__))
        kat_file = os.path.join(script_dir, "test_vectors", self.kat_combo.currentText())
        self._set_status("Running KAT...", "orange")
        self._run_subprocess([exe, "--kat", kat_file], self.kat_output, self.kat_run_btn, self.kat_stop_btn)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = Lab4GUI()
    gui.show()
    sys.exit(app.exec())
