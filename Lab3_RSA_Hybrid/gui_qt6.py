#!/usr/bin/env python3
"""Lab 3 RSA-OAEP & Hybrid Encryption GUI - DLL + subprocess mode"""

import sys
import os
import ctypes
import subprocess
import struct
import json
import base64
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QTabWidget, QPushButton, QLineEdit, QTextEdit, QLabel, QComboBox,
    QSpinBox, QGroupBox, QFileDialog, QMessageBox, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject


# =============================================================================
# DLL Wrapper
# =============================================================================
class RSAEngine:
    """Wrapper around rsatool.dll using ctypes."""

    def __init__(self, dll_path):
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"DLL not found: {dll_path}")
        dll_dir = os.path.dirname(os.path.abspath(dll_path))
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if hasattr(os, 'add_dll_directory'):
            os.add_dll_directory(dll_dir)
            os.add_dll_directory(script_dir)
        os.environ['PATH'] = dll_dir + os.pathsep + script_dir + os.pathsep + os.environ.get('PATH', '')
        self.dll = ctypes.CDLL(dll_path)

        self.dll.lab3_keygen.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.dll.lab3_keygen.restype = ctypes.c_int

        self.dll.lab3_encrypt.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        self.dll.lab3_encrypt.restype = ctypes.c_char_p

        self.dll.lab3_decrypt.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p
        ]
        self.dll.lab3_decrypt.restype = ctypes.c_int

        self.dll.lab3_run_benchmark.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.dll.lab3_run_benchmark.restype = ctypes.c_char_p

        self.dll.lab3_run_tests.argtypes = [
            ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int), ctypes.c_char_p
        ]
        self.dll.lab3_run_tests.restype = ctypes.c_char_p

        self.dll.lab3_run_kat.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.dll.lab3_run_kat.restype = ctypes.c_char_p

    def keygen(self, bits, pub_file, priv_file):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab3_keygen(bits, pub_file.encode(), priv_file.encode(), error_buf)
        if result != 0:
            raise RuntimeError(error_buf.value.decode('utf-8'))

    def encrypt(self, pub_key_file, plaintext, label, output_file, aad_hex=""):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab3_encrypt(
            pub_key_file.encode(), plaintext.encode(),
            label.encode() if label else b"",
            aad_hex.encode() if aad_hex else b"",
            output_file.encode(), error_buf
        )
        if result is None:
            raise RuntimeError(error_buf.value.decode('utf-8'))
        return result.decode('utf-8')

    def decrypt(self, priv_key_file, input_file, label, output_file):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab3_decrypt(
            priv_key_file.encode(), input_file.encode(),
            label.encode() if label else b"",
            output_file.encode(), error_buf
        )
        if result != 0:
            raise RuntimeError(error_buf.value.decode('utf-8'))


# =============================================================================
# Subprocess Worker Thread
# =============================================================================
class SubprocessWorker(QThread):
    output_ready = pyqtSignal(str)
    finished_signal = pyqtSignal(int, str)

    def __init__(self, cmd, cwd=None, parent=None):
        super().__init__(parent)
        self.cmd = cmd
        self.cwd = cwd
        self._process = None

    def run(self):
        try:
            self._process = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                cwd=self.cwd, text=True, encoding='utf-8', errors='replace'
            )
            output_lines = []
            for line in self._process.stdout:
                self.output_ready.emit(line)
                output_lines.append(line)
            self._process.wait()
            self.finished_signal.emit(self._process.returncode, ''.join(output_lines))
        except FileNotFoundError:
            self.finished_signal.emit(-1, f"[ERROR] Executable not found: {self.cmd[0]}")
        except Exception as e:
            self.finished_signal.emit(-1, f"[ERROR] {e}")

    def stop(self):
        if self._process and self._process.poll() is None:
            self._process.terminate()


# =============================================================================
# Envelope Inspector
# =============================================================================
def inspect_envelope(filepath):
    """Parse hybrid envelope and return human-readable summary."""
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(4)
            if len(raw) < 4:
                return "Not a valid envelope (too small)"
            header_size = struct.unpack('<I', raw)[0]
            header_bytes = f.read(header_size)
            ct_size = len(f.read())
        header = json.loads(header_bytes.decode('utf-8'))
        lines = [
            "=== Hybrid Envelope ===",
            f"Mode        : {header.get('mode', 'N/A')}",
            f"RSA Modulus : {header.get('rsa_modulus', 'N/A')} bits",
            f"Hash        : {header.get('hash', 'N/A')}",
            f"Wrapped Key : {header.get('wrapped_key', '')[:40]}... (base64)",
            f"IV          : {header.get('iv', 'N/A')}",
            f"Tag         : {header.get('tag', 'N/A')}",
            f"AAD         : {header.get('aad', '(none)') or '(none)'}",
            f"Header Size : {header_size} bytes",
            f"Ciphertext  : {ct_size} bytes",
        ]
        return '\n'.join(lines)
    except Exception as e:
        return f"[ERROR] Cannot parse envelope: {e}"


# =============================================================================
# Main GUI
# =============================================================================
class Lab3GUI(QWidget):
    def __init__(self):
        super().__init__()
        self.engine = None
        self._worker = None
        self._build_dir = ""  # Auto-set from DLL path on load
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Lab 3 - RSA-OAEP & Hybrid Encryption")
        self.resize(900, 820)

        main_layout = QVBoxLayout(self)

        # DLL path selector
        dll_group = QGroupBox("Select DLL Library (rsatool.dll)")
        dll_layout = QHBoxLayout()
        self.dll_path = QLineEdit()
        self.dll_path.setPlaceholderText("Select rsatool.dll...")
        dll_btn = QPushButton("Browse...")
        dll_btn.clicked.connect(self.browse_dll)
        dll_layout.addWidget(self.dll_path)
        dll_layout.addWidget(dll_btn)
        load_btn = QPushButton("Load DLL")
        load_btn.clicked.connect(self.load_dll)
        dll_layout.addWidget(load_btn)
        dll_group.setLayout(dll_layout)
        main_layout.addWidget(dll_group)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_keygen_tab(), "Key Generation")
        self.tabs.addTab(self.create_encrypt_tab(), "Encryption")
        self.tabs.addTab(self.create_decrypt_tab(), "Decryption")
        self.tabs.addTab(self.create_hybrid_tab(), "Hybrid Mode")
        self.tabs.addTab(self.create_benchmark_tab(), "Benchmark")
        self.tabs.addTab(self.create_catch2_tab(), "Catch2 Tests")
        self.tabs.addTab(self.create_kat_tab(), "KAT Tests")
        main_layout.addWidget(self.tabs)

        # Status bar
        self.status_bar = QLabel("Status: DLL not loaded")
        self.status_bar.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(self.status_bar)

    # =========================================================================
    # Tab: Key Generation
    # =========================================================================
    def create_keygen_tab(self):
        tab = QWidget()
        layout = QFormLayout(tab)
        self.bits_combo = QComboBox()
        self.bits_combo.addItems(["3072", "4096"])
        layout.addRow("Key Size (bits):", self.bits_combo)
        pub_layout = QHBoxLayout()
        self.pub_key_edit = QLineEdit()
        self.pub_key_edit.setPlaceholderText("public_key.pem")
        pub_browse = QPushButton("Browse...")
        pub_browse.clicked.connect(self.browse_pub_save)
        pub_layout.addWidget(self.pub_key_edit); pub_layout.addWidget(pub_browse)
        layout.addRow("Public Key:", pub_layout)
        priv_layout = QHBoxLayout()
        self.priv_key_edit = QLineEdit()
        self.priv_key_edit.setPlaceholderText("private_key.pem")
        priv_browse = QPushButton("Browse...")
        priv_browse.clicked.connect(self.browse_priv_save)
        priv_layout.addWidget(self.priv_key_edit); priv_layout.addWidget(priv_browse)
        layout.addRow("Private Key:", priv_layout)
        self.keygen_btn = QPushButton("Generate Key Pair")
        self.keygen_btn.clicked.connect(self.do_keygen)
        self.keygen_btn.setEnabled(False)
        layout.addRow(self.keygen_btn)
        return tab

    # =========================================================================
    # Tab: Encryption
    # =========================================================================
    def create_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        pub_layout = QHBoxLayout()
        self.enc_pub_edit = QLineEdit(); self.enc_pub_edit.setPlaceholderText("Load public key...")
        pub_browse = QPushButton("Browse..."); pub_browse.clicked.connect(self.browse_pub_key)
        pub_layout.addWidget(self.enc_pub_edit); pub_layout.addWidget(pub_browse)
        layout.addWidget(QLabel("Public Key:")); layout.addLayout(pub_layout)
        self.label_edit = QLineEdit(); self.label_edit.setPlaceholderText("Optional OAEP label")
        layout.addWidget(QLabel("OAEP Label (optional):")); layout.addWidget(self.label_edit)
        self.plaintext_edit = QTextEdit(); self.plaintext_edit.setPlaceholderText("Enter plaintext...")
        self.plaintext_edit.setMaximumHeight(100)
        layout.addWidget(QLabel("Plaintext:")); layout.addWidget(self.plaintext_edit)
        out_layout = QHBoxLayout()
        self.out_file_edit = QLineEdit(); self.out_file_edit.setPlaceholderText("output.bin")
        out_browse = QPushButton("Browse..."); out_browse.clicked.connect(self.browse_enc_output)
        out_layout.addWidget(self.out_file_edit); out_layout.addWidget(out_browse)
        layout.addWidget(QLabel("Output File:")); layout.addLayout(out_layout)
        self.encrypt_btn = QPushButton("Encrypt"); self.encrypt_btn.clicked.connect(self.do_encrypt)
        self.encrypt_btn.setEnabled(False); layout.addWidget(self.encrypt_btn)
        self.enc_result = QTextEdit(); self.enc_result.setReadOnly(True); self.enc_result.setMaximumHeight(100)
        layout.addWidget(QLabel("Result:")); layout.addWidget(self.enc_result)
        return tab

    # =========================================================================
    # Tab: Decryption
    # =========================================================================
    def create_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        priv_layout = QHBoxLayout()
        self.dec_priv_edit = QLineEdit(); self.dec_priv_edit.setPlaceholderText("Load private key...")
        priv_browse = QPushButton("Browse..."); priv_browse.clicked.connect(self.browse_priv_key)
        priv_layout.addWidget(self.dec_priv_edit); priv_layout.addWidget(priv_browse)
        layout.addWidget(QLabel("Private Key:")); layout.addLayout(priv_layout)
        in_layout = QHBoxLayout()
        self.in_file_edit = QLineEdit(); self.in_file_edit.setPlaceholderText("Select input file...")
        in_browse = QPushButton("Browse..."); in_browse.clicked.connect(self.browse_input_file)
        in_layout.addWidget(self.in_file_edit); in_layout.addWidget(in_browse)
        layout.addWidget(QLabel("Input File:")); layout.addLayout(in_layout)
        self.dec_label_edit = QLineEdit(); self.dec_label_edit.setPlaceholderText("Optional OAEP label")
        layout.addWidget(QLabel("OAEP Label (optional):")); layout.addWidget(self.dec_label_edit)
        out_layout = QHBoxLayout()
        self.dec_out_edit = QLineEdit(); self.dec_out_edit.setPlaceholderText("output.txt")
        out_browse = QPushButton("Browse..."); out_browse.clicked.connect(self.browse_dec_output)
        out_layout.addWidget(self.dec_out_edit); out_layout.addWidget(out_browse)
        layout.addWidget(QLabel("Output File:")); layout.addLayout(out_layout)
        self.decrypt_btn = QPushButton("Decrypt"); self.decrypt_btn.clicked.connect(self.do_decrypt)
        self.decrypt_btn.setEnabled(False); layout.addWidget(self.decrypt_btn)
        self.dec_result = QTextEdit(); self.dec_result.setReadOnly(True); self.dec_result.setMaximumHeight(100)
        layout.addWidget(QLabel("Decrypted Text:")); layout.addWidget(self.dec_result)
        return tab

    # =========================================================================
    # Tab: Hybrid Mode
    # =========================================================================
    def create_hybrid_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        # --- Encrypt ---
        enc_group = QGroupBox("Hybrid Encryption (RSA-OAEP + AES-256-GCM)")
        enc_layout = QVBoxLayout(enc_group)
        pub_l = QHBoxLayout()
        self.hyb_pub_edit = QLineEdit(); self.hyb_pub_edit.setPlaceholderText("Public key PEM...")
        pb = QPushButton("Browse..."); pb.clicked.connect(self.browse_hyb_pub)
        pub_l.addWidget(self.hyb_pub_edit); pub_l.addWidget(pb)
        enc_layout.addWidget(QLabel("Public Key:")); enc_layout.addLayout(pub_l)
        self.hyb_label_edit = QLineEdit(); self.hyb_label_edit.setPlaceholderText("OAEP label (must match on decrypt)")
        enc_layout.addWidget(QLabel("OAEP Label (optional):")); enc_layout.addWidget(self.hyb_label_edit)
        self.hyb_aad_edit = QLineEdit(); self.hyb_aad_edit.setPlaceholderText("AAD hex (e.g. 48656c6c6f) — authenticated, NOT encrypted")
        enc_layout.addWidget(QLabel("AAD (hex, optional):")); enc_layout.addWidget(self.hyb_aad_edit)
        self.hyb_plaintext = QTextEdit()
        self.hyb_plaintext.setPlaceholderText("Enter plaintext.\n• ≤318 chars (RSA-3072) w/o AAD → direct RSA-OAEP\n• >318 chars OR with AAD → hybrid (RSA-OAEP + AES-GCM)")
        self.hyb_plaintext.setMaximumHeight(90)
        enc_layout.addWidget(QLabel("Plaintext:")); enc_layout.addWidget(self.hyb_plaintext)
        out_l = QHBoxLayout()
        self.hyb_out_edit = QLineEdit(); self.hyb_out_edit.setPlaceholderText("hybrid_envelope.bin")
        ob = QPushButton("Browse..."); ob.clicked.connect(self.browse_hyb_output)
        out_l.addWidget(self.hyb_out_edit); out_l.addWidget(ob)
        enc_layout.addWidget(QLabel("Output Envelope:")); enc_layout.addLayout(out_l)
        self.hyb_encrypt_btn = QPushButton("Encrypt (Hybrid)"); self.hyb_encrypt_btn.clicked.connect(self.do_hybrid_encrypt)
        self.hyb_encrypt_btn.setEnabled(False); enc_layout.addWidget(self.hyb_encrypt_btn)
        layout.addWidget(enc_group)
        # --- Decrypt ---
        dec_group = QGroupBox("Hybrid Decryption")
        dec_layout = QVBoxLayout(dec_group)
        priv_l = QHBoxLayout()
        self.hyb_priv_edit = QLineEdit(); self.hyb_priv_edit.setPlaceholderText("Private key PEM...")
        pb2 = QPushButton("Browse..."); pb2.clicked.connect(self.browse_hyb_priv)
        priv_l.addWidget(self.hyb_priv_edit); priv_l.addWidget(pb2)
        dec_layout.addWidget(QLabel("Private Key:")); dec_layout.addLayout(priv_l)
        self.hyb_dec_label_edit = QLineEdit(); self.hyb_dec_label_edit.setPlaceholderText("OAEP label (must match)")
        dec_layout.addWidget(QLabel("OAEP Label (optional):")); dec_layout.addWidget(self.hyb_dec_label_edit)
        in_l = QHBoxLayout()
        self.hyb_in_edit = QLineEdit(); self.hyb_in_edit.setPlaceholderText("hybrid_envelope.bin")
        ib = QPushButton("Browse..."); ib.clicked.connect(self.browse_hyb_input)
        in_l.addWidget(self.hyb_in_edit); in_l.addWidget(ib)
        dec_layout.addWidget(QLabel("Input Envelope:")); dec_layout.addLayout(in_l)
        out_l2 = QHBoxLayout()
        self.hyb_dec_out_edit = QLineEdit(); self.hyb_dec_out_edit.setPlaceholderText("decrypted_output.bin")
        ob2 = QPushButton("Browse..."); ob2.clicked.connect(self.browse_hyb_dec_output)
        out_l2.addWidget(self.hyb_dec_out_edit); out_l2.addWidget(ob2)
        dec_layout.addWidget(QLabel("Decrypted Output:")); dec_layout.addLayout(out_l2)
        self.hyb_decrypt_btn = QPushButton("Decrypt (Hybrid)"); self.hyb_decrypt_btn.clicked.connect(self.do_hybrid_decrypt)
        self.hyb_decrypt_btn.setEnabled(False); dec_layout.addWidget(self.hyb_decrypt_btn)
        layout.addWidget(dec_group)
        # --- Envelope inspector ---
        self.hyb_envelope_info = QTextEdit(); self.hyb_envelope_info.setReadOnly(True)
        self.hyb_envelope_info.setMaximumHeight(160)
        layout.addWidget(QLabel("Result / Envelope Info:")); layout.addWidget(self.hyb_envelope_info)
        return tab

    # =========================================================================
    # Tab: Benchmark
    # =========================================================================
    def create_benchmark_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        opt = QHBoxLayout()
        opt.addWidget(QLabel("Threads:"))
        self.bm_threads = QSpinBox(); self.bm_threads.setRange(0, 64); self.bm_threads.setValue(0)
        self.bm_threads.setToolTip("0 = auto-detect CPU count"); opt.addWidget(self.bm_threads)
        opt.addStretch()
        layout.addLayout(opt)
        btn_l = QHBoxLayout()
        self.bm_run_btn = QPushButton("Run Benchmark"); self.bm_run_btn.clicked.connect(self.do_benchmark)
        btn_l.addWidget(self.bm_run_btn)
        self.bm_stop_btn = QPushButton("Stop"); self.bm_stop_btn.clicked.connect(self.stop_worker)
        self.bm_stop_btn.setEnabled(False); btn_l.addWidget(self.bm_stop_btn)
        layout.addLayout(btn_l)
        self.bm_output = QTextEdit(); self.bm_output.setReadOnly(True); self.bm_output.setFont(self._mono_font())
        layout.addWidget(QLabel("Benchmark Output:")); layout.addWidget(self.bm_output)
        return tab

    # =========================================================================
    # Tab: Catch2 Tests
    # =========================================================================
    def create_catch2_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        info = QLabel("Runs Catch2 unit tests (catch2_test.exe).\nTests: RSA-OAEP, Hybrid, Negative, Encoding, DER.")
        info.setWordWrap(True); layout.addWidget(info)
        btn_l = QHBoxLayout()
        self.ct_run_btn = QPushButton("Run Catch2 Tests"); self.ct_run_btn.clicked.connect(self.do_catch2)
        btn_l.addWidget(self.ct_run_btn)
        self.ct_stop_btn = QPushButton("Stop"); self.ct_stop_btn.clicked.connect(self.stop_worker)
        self.ct_stop_btn.setEnabled(False); btn_l.addWidget(self.ct_stop_btn)
        layout.addLayout(btn_l)
        self.ct_output = QTextEdit(); self.ct_output.setReadOnly(True); self.ct_output.setFont(self._mono_font())
        layout.addWidget(QLabel("Test Output:")); layout.addWidget(self.ct_output)
        return tab

    # =========================================================================
    # Tab: KAT Tests
    # =========================================================================
    def create_kat_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        info = QLabel("Runs Known Answer Tests: rsatool --kat <vectors.json>.")
        info.setWordWrap(True); layout.addWidget(info)
        kat_l = QHBoxLayout()
        self.kat_file_edit = QLineEdit(); self.kat_file_edit.setPlaceholderText("Select KAT JSON file...")
        kb = QPushButton("Browse..."); kb.clicked.connect(self.browse_kat_file)
        kat_l.addWidget(self.kat_file_edit); kat_l.addWidget(kb)
        lab_dir = os.path.dirname(os.path.abspath(__file__))
        rsa_btn = QPushButton("RSA-OAEP KATs")
        rsa_btn.clicked.connect(lambda: self.kat_file_edit.setText(os.path.join(lab_dir, "test_vectors", "rsa_oaep_kats.json")))
        kat_l.addWidget(rsa_btn)
        hyb_btn = QPushButton("Hybrid KATs")
        hyb_btn.clicked.connect(lambda: self.kat_file_edit.setText(os.path.join(lab_dir, "test_vectors", "hybrid_kats.json")))
        kat_l.addWidget(hyb_btn)
        layout.addLayout(kat_l)
        btn_l = QHBoxLayout()
        self.kat_run_btn = QPushButton("Run KAT Tests"); self.kat_run_btn.clicked.connect(self.do_kat)
        btn_l.addWidget(self.kat_run_btn)
        self.kat_stop_btn = QPushButton("Stop"); self.kat_stop_btn.clicked.connect(self.stop_worker)
        self.kat_stop_btn.setEnabled(False); btn_l.addWidget(self.kat_stop_btn)
        layout.addLayout(btn_l)
        self.kat_output = QTextEdit(); self.kat_output.setReadOnly(True); self.kat_output.setFont(self._mono_font())
        layout.addWidget(QLabel("KAT Output:")); layout.addWidget(self.kat_output)
        return tab

    # =========================================================================
    # Helpers
    # =========================================================================
    def _mono_font(self):
        from PyQt6.QtGui import QFont
        f = QFont("Consolas", 9); f.setStyleHint(QFont.StyleHint.Monospace); return f

    def _set_status(self, msg, color="blue"):
        self.status_bar.setText(f"Status: {msg}")
        self.status_bar.setStyleSheet(f"color: {color}; font-weight: bold;")

    def _get_exe_path(self, name):
        build_dir = self._build_dir
        if not build_dir:
            QMessageBox.warning(self, "Error", "Please load the DLL first (build directory is auto-detected from DLL path).")
            return None
        for ext in ['.exe', '']:
            path = os.path.join(build_dir, name + ext)
            if os.path.exists(path):
                return path
        QMessageBox.warning(self, "Error", f"Executable not found: {name} in {build_dir}")
        return None

    def _run_subprocess(self, cmd, output_widget, run_btn, stop_btn):
        output_widget.clear(); run_btn.setEnabled(False); stop_btn.setEnabled(True)
        self._worker = SubprocessWorker(cmd, cwd=self._build_dir or None)
        self._worker.output_ready.connect(lambda line: output_widget.append(line.rstrip()))
        self._worker.finished_signal.connect(lambda code, _: self._on_worker_done(code, run_btn, stop_btn))
        self._worker.start()

    def _on_worker_done(self, returncode, run_btn, stop_btn):
        run_btn.setEnabled(True); stop_btn.setEnabled(False)
        if returncode == 0:
            self._set_status("Completed successfully", "green")
        else:
            self._set_status(f"Exited with code {returncode}", "red")

    def stop_worker(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()

    # =========================================================================
    # DLL Actions
    # =========================================================================
    def load_dll(self):
        try:
            path = self.dll_path.text()
            if not path:
                QMessageBox.warning(self, "Error", "Please select a DLL file"); return
            self.engine = RSAEngine(path)
            dll_dir = os.path.dirname(os.path.abspath(path))
            self._build_dir = dll_dir
            self._set_status(f"DLL loaded — build dir: {dll_dir}", "green")
            for btn in [self.keygen_btn, self.encrypt_btn, self.decrypt_btn,
                        self.hyb_encrypt_btn, self.hyb_decrypt_btn]:
                btn.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load DLL: {e}")

    def do_keygen(self):
        try:
            bits = int(self.bits_combo.currentText())
            pub_file = self.pub_key_edit.text(); priv_file = self.priv_key_edit.text()
            if not pub_file or not priv_file:
                QMessageBox.warning(self, "Error", "Please specify both key file paths"); return
            self.engine.keygen(bits, pub_file, priv_file)
            self._set_status(f"Generated RSA-{bits} key pair", "blue")
            QMessageBox.information(self, "Success", f"RSA-{bits} key pair generated")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation failed: {e}")

    def do_encrypt(self):
        try:
            pub_file = self.enc_pub_edit.text()
            if not pub_file: QMessageBox.warning(self, "Error", "Please load a public key"); return
            out_file = self.out_file_edit.text()
            if not out_file: QMessageBox.warning(self, "Error", "Please specify an output file"); return
            result = self.engine.encrypt(pub_file, self.plaintext_edit.toPlainText(), self.label_edit.text(), out_file)
            self.enc_result.setText(result); self._set_status("Encryption successful", "blue")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {e}")

    def do_decrypt(self):
        try:
            priv_file = self.dec_priv_edit.text()
            if not priv_file: QMessageBox.warning(self, "Error", "Please load a private key"); return
            in_file = self.in_file_edit.text()
            if not in_file: QMessageBox.warning(self, "Error", "Please select an input file"); return
            out_file = self.dec_out_edit.text()
            if not out_file: QMessageBox.warning(self, "Error", "Please specify an output file"); return
            self.engine.decrypt(priv_file, in_file, self.dec_label_edit.text(), out_file)
            with open(out_file, 'r', encoding='utf-8', errors='replace') as f:
                self.dec_result.setText(f.read())
            self._set_status("Decryption successful", "blue")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {e}")

    # =========================================================================
    # Hybrid Mode Actions
    # =========================================================================
    def do_hybrid_encrypt(self):
        try:
            pub_file = self.hyb_pub_edit.text()
            if not pub_file: QMessageBox.warning(self, "Error", "Please select a public key"); return
            out_file = self.hyb_out_edit.text()
            if not out_file: QMessageBox.warning(self, "Error", "Please specify an output file"); return
            plaintext = self.hyb_plaintext.toPlainText()
            aad_hex = self.hyb_aad_edit.text().strip()
            label = self.hyb_label_edit.text()
            result = self.engine.encrypt(pub_file, plaintext, label, out_file, aad_hex)
            info = [f"[ENCRYPT] Mode: {'Hybrid' if 'Hybrid' in result else 'RSA-OAEP / Hybrid'}",
                    f"[ENCRYPT] Plaintext size: {len(plaintext.encode('utf-8'))} bytes"]
            if aad_hex: info.append(f"[ENCRYPT] AAD (hex): {aad_hex}")
            if label: info.append(f"[ENCRYPT] OAEP label: {label}")
            info.append(f"[ENCRYPT] Output: {out_file}\n")
            if os.path.exists(out_file): info.append(inspect_envelope(out_file))
            self.hyb_envelope_info.setText('\n'.join(info))
            self._set_status("Hybrid encryption successful", "blue")
        except Exception as e:
            self.hyb_envelope_info.setText(f"[ERROR] {e}")
            QMessageBox.critical(self, "Error", f"Hybrid encryption failed: {e}")

    def do_hybrid_decrypt(self):
        try:
            priv_file = self.hyb_priv_edit.text()
            if not priv_file: QMessageBox.warning(self, "Error", "Please select a private key"); return
            in_file = self.hyb_in_edit.text()
            if not in_file: QMessageBox.warning(self, "Error", "Please select an input envelope"); return
            out_file = self.hyb_dec_out_edit.text()
            if not out_file: QMessageBox.warning(self, "Error", "Please specify an output file"); return
            label = self.hyb_dec_label_edit.text()
            self.engine.decrypt(priv_file, in_file, label, out_file)
            try:
                with open(out_file, 'r', encoding='utf-8', errors='replace') as f: dec_text = f.read()
            except Exception: dec_text = f"(Binary output saved to: {out_file})"
            info = ["[DECRYPT] Success!", f"[DECRYPT] Input: {in_file}", f"[DECRYPT] Output: {out_file}",
                    f"[DECRYPT] Decrypted size: {os.path.getsize(out_file)} bytes", "",
                    "--- Decrypted Content ---", dec_text[:2000]]
            if len(dec_text) > 2000: info.append(f"... (truncated, full in {out_file})")
            self.hyb_envelope_info.setText('\n'.join(info))
            self._set_status("Hybrid decryption successful", "blue")
        except Exception as e:
            self.hyb_envelope_info.setText(f"[ERROR] {e}")
            QMessageBox.critical(self, "Error", f"Hybrid decryption failed: {e}")

    # =========================================================================
    # Benchmark / Catch2 / KAT Actions
    # =========================================================================
    def do_benchmark(self):
        exe = self._get_exe_path("benchmark")
        if not exe: return
        cmd = [exe]
        t = self.bm_threads.value()
        if t != 1: cmd += ["--threads", str(t)]
        cmd += ["--verbose"]
        self._set_status("Running benchmark...", "orange")
        self._run_subprocess(cmd, self.bm_output, self.bm_run_btn, self.bm_stop_btn)

    def do_catch2(self):
        exe = self._get_exe_path("catch2_test")
        if not exe: return
        self._set_status("Running Catch2 tests...", "orange")
        self._run_subprocess([exe, "--reporter", "console"], self.ct_output, self.ct_run_btn, self.ct_stop_btn)

    def do_kat(self):
        exe = self._get_exe_path("rsatool")
        if not exe: return
        kat_file = self.kat_file_edit.text().strip()
        if not kat_file or not os.path.exists(kat_file):
            QMessageBox.warning(self, "Error", "Please select a valid KAT JSON file"); return
        self._set_status("Running KAT tests...", "orange")
        self._run_subprocess([exe, "--kat", kat_file], self.kat_output, self.kat_run_btn, self.kat_stop_btn)

    # =========================================================================
    # Browse dialogs
    # =========================================================================
    def browse_dll(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select DLL", "", "DLL Files (*.dll);;All Files (*)")
        if p: self.dll_path.setText(p)

    def browse_pub_save(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Public Key", "pub_key.pem", "PEM Files (*.pem)")
        if p: self.pub_key_edit.setText(p)

    def browse_priv_save(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "priv_key.pem", "PEM Files (*.pem)")
        if p: self.priv_key_edit.setText(p)

    def browse_pub_key(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Public Key", "", "PEM Files (*.pem)")
        if p: self.enc_pub_edit.setText(p)

    def browse_priv_key(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Private Key", "", "PEM Files (*.pem)")
        if p: self.dec_priv_edit.setText(p)

    def browse_enc_output(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Output", "output.bin", "All Files (*)")
        if p: self.out_file_edit.setText(p)

    def browse_dec_output(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Decrypted", "output.txt", "All Files (*)")
        if p: self.dec_out_edit.setText(p)

    def browse_input_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Input File", "", "All Files (*)")
        if p: self.in_file_edit.setText(p)

    def browse_kat_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select KAT Vectors", "", "JSON Files (*.json)")
        if p: self.kat_file_edit.setText(p)

    def browse_hyb_pub(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Public Key", "", "PEM Files (*.pem)")
        if p: self.hyb_pub_edit.setText(p)

    def browse_hyb_priv(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Private Key", "", "PEM Files (*.pem)")
        if p: self.hyb_priv_edit.setText(p)

    def browse_hyb_output(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Envelope", "hybrid_envelope.bin", "All Files (*)")
        if p: self.hyb_out_edit.setText(p)

    def browse_hyb_input(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Envelope", "", "All Files (*)")
        if p: self.hyb_in_edit.setText(p)

    def browse_hyb_dec_output(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Decrypted", "decrypted_output.bin", "All Files (*)")
        if p: self.hyb_dec_out_edit.setText(p)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = Lab3GUI()
    gui.show()
    sys.exit(app.exec())
