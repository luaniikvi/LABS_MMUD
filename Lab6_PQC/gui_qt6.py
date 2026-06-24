#!/usr/bin/env python3
"""Lab 6 Post-Quantum Crypto (ML-DSA, ML-KEM) GUI - DLL + subprocess mode"""

import sys
import os
import ctypes
import subprocess
import json
import tempfile
import shutil
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QTabWidget, QPushButton, QLineEdit, QTextEdit, QLabel, QComboBox,
    QSpinBox, QGroupBox, QFileDialog, QMessageBox, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


# =============================================================================
# DLL Wrapper
# =============================================================================
class PQEngine:
    """Wrapper around pqtool.dll using ctypes."""

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

        self.dll.lab6_keygen.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.dll.lab6_keygen.restype = ctypes.c_int

        self.dll.lab6_sign.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_int, ctypes.c_char_p
        ]
        self.dll.lab6_sign.restype = ctypes.c_char_p

        self.dll.lab6_verify.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_char_p
        ]
        self.dll.lab6_verify.restype = ctypes.c_int

        self.dll.lab6_encaps.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        self.dll.lab6_encaps.restype = ctypes.c_char_p

        self.dll.lab6_decaps.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        self.dll.lab6_decaps.restype = ctypes.c_int

        self.dll.lab6_run_tests.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
                                            ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]
        self.dll.lab6_run_tests.restype = ctypes.c_char_p

        self.dll.lab6_run_kat.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.dll.lab6_run_kat.restype = ctypes.c_char_p

    def keygen(self, algo, pub_file, priv_file):
        error_buf = ctypes.create_string_buffer(1024)
        rc = self.dll.lab6_keygen(algo.encode(), pub_file.encode(), priv_file.encode(), error_buf)
        if rc != 0:
            raise RuntimeError(error_buf.value.decode())
        return True

    def sign(self, algo, hash_algo, priv_key_file, message_bytes, output_file, encode_mode=0):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab6_sign(
            algo.encode(), hash_algo.encode(), priv_key_file.encode(),
            message_bytes, len(message_bytes),
            output_file.encode() if output_file else b'',
            encode_mode, error_buf
        )
        if not result:
            raise RuntimeError(error_buf.value.decode())
        return result.decode() if result else ""

    def verify(self, algo, hash_algo, pub_key_file, message_bytes, sig_file):
        error_buf = ctypes.create_string_buffer(1024)
        rc = self.dll.lab6_verify(
            algo.encode(), hash_algo.encode(), pub_key_file.encode(),
            message_bytes, len(message_bytes),
            sig_file.encode(), error_buf
        )
        if rc < 0:
            raise RuntimeError(error_buf.value.decode())
        return bool(rc)

    def encaps(self, algo, pub_key_file, ct_file, ss_file):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab6_encaps(algo.encode(), pub_key_file.encode(),
                                       ct_file.encode(), ss_file.encode(), error_buf)
        if not result:
            raise RuntimeError(error_buf.value.decode())
        return result.decode()

    def decaps(self, algo, priv_key_file, ct_file, ss_file):
        error_buf = ctypes.create_string_buffer(1024)
        rc = self.dll.lab6_decaps(algo.encode(), priv_key_file.encode(),
                                   ct_file.encode(), ss_file.encode(), error_buf)
        if rc < 0:
            raise RuntimeError(error_buf.value.decode())
        return bool(rc)

    def run_tests(self):
        total = ctypes.c_int(0); passed = ctypes.c_int(0); failed = ctypes.c_int(0)
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab6_run_tests(ctypes.byref(total), ctypes.byref(passed),
                                          ctypes.byref(failed), error_buf)
        if not result:
            return f"ERROR: {error_buf.value.decode()}"
        return result.decode()

    def run_kat(self, vectors_file):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab6_run_kat(vectors_file.encode(), error_buf)
        if not result:
            return f"ERROR: {error_buf.value.decode()}"
        return result.decode()


# =============================================================================
# Worker Thread
# =============================================================================
class WorkerThread(QThread):
    finished = pyqtSignal(str)

    def __init__(self, target):
        super().__init__()
        self._target = target

    def run(self):
        try:
            result = self._target()
            self.finished.emit(str(result))
        except Exception as e:
            self.finished.emit(f"ERROR: {str(e)}")


# =============================================================================
# Subprocess Helpers
# =============================================================================
def _find_exe(exe_name):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "build", "Release", exe_name),
        os.path.join(script_dir, "build", exe_name),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def _find_dll():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for p in [os.path.join(script_dir, "build", "Release", "pqtool.dll"),
              os.path.join(script_dir, "build", "pqtool.dll")]:
        if os.path.exists(p):
            return p
    return None


def _run_in_temp(exe, args, timeout=600):
    cwd = tempfile.mkdtemp(prefix="lab6_")
    try:
        result = subprocess.run([exe] + args, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        out = result.stdout
        if result.stderr:
            out += "\n" + result.stderr
        return out
    except subprocess.TimeoutExpired:
        return "[ERROR] Timed out."
    except Exception as e:
        return f"[ERROR] {e}"
    finally:
        shutil.rmtree(cwd, ignore_errors=True)


# =============================================================================
# GUI Window
# =============================================================================
class Lab6Window(QWidget):
    def __init__(self, engine=None, dll_path=None):
        super().__init__()
        self.engine = engine
        self.dll_path = dll_path
        self.pqtool_exe = _find_exe("pqtool.exe")
        self.benchmark_exe = _find_exe("benchmark.exe")
        self._worker = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Lab 6 — Post-Quantum Crypto (ML-DSA, ML-KEM)")
        self.setMinimumSize(950, 750)
        main_layout = QVBoxLayout()
        tabs = QTabWidget()

        tabs.addTab(self._create_keygen_tab(), "Key Generation")
        tabs.addTab(self._create_sign_tab(), "Sign (ML-DSA)")
        tabs.addTab(self._create_verify_tab(), "Verify (ML-DSA)")
        tabs.addTab(self._create_kem_tab(), "KEM (ML-KEM)")
        tabs.addTab(self._create_cert_tab(), "Certificate")
        tabs.addTab(self._create_tests_tab(), "Tests")
        tabs.addTab(self._create_benchmark_tab(), "Benchmark")

        # DLL toolbar
        status_layout = QHBoxLayout()
        dll_label = QLabel("DLL:")
        self.dll_path_edit = QLineEdit()
        self.dll_path_edit.setReadOnly(True)
        if self.dll_path:
            self.dll_path_edit.setText(self.dll_path)
        self.dll_path_edit.setPlaceholderText("No DLL loaded — will use CLI subprocess")

        btn_load = QPushButton("Load")
        btn_load.clicked.connect(self._load_dll)
        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self._browse_dll)

        status_layout.addWidget(dll_label)
        status_layout.addWidget(self.dll_path_edit, 1)
        status_layout.addWidget(btn_load)
        status_layout.addWidget(btn_browse)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setMinimumHeight(150)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(tabs)
        splitter.addWidget(self.output_area)
        splitter.setSizes([500, 200])

        main_layout.addLayout(status_layout)
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

    def log(self, msg):
        self.output_area.append(msg)

    def _load_dll(self):
        path = _find_dll()
        if not path:
            QMessageBox.warning(self, "Not Found", "pqtool.dll not found.")
            return
        try:
            self.engine = PQEngine(path)
            self.dll_path = path
            self.dll_path_edit.setText(path)
            self.log(f"[INFO] Loaded DLL: {path}")
        except Exception as e:
            QMessageBox.warning(self, "DLL Error", str(e))

    def _browse_dll(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select pqtool.dll", "", "DLL files (*.dll)")
        if not path:
            return
        try:
            self.engine = PQEngine(path)
            self.dll_path = path
            self.dll_path_edit.setText(path)
            self.log(f"[INFO] Loaded DLL: {path}")
        except Exception as e:
            QMessageBox.warning(self, "DLL Error", str(e))

    def _browse_open(self, widget):
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path:
            widget.setText(path)

    def _browse_save(self, widget):
        path, _ = QFileDialog.getSaveFileName(self, "Save file")
        if path:
            widget.setText(path)

    # --- Tab: Key Generation ---
    def _create_keygen_tab(self):
        tab = QWidget(); layout = QVBoxLayout(); form = QFormLayout()
        self.kg_algo = QComboBox()
        self.kg_algo.addItems(["mldsa-44", "mldsa-65", "mlkem-512"])
        form.addRow("Algorithm:", self.kg_algo)

        self.kg_pub = QLineEdit(); self.kg_pub.setPlaceholderText("pub.pem")
        b = QPushButton("Browse..."); b.clicked.connect(lambda: self._browse_save(self.kg_pub))
        h = QHBoxLayout(); h.addWidget(self.kg_pub); h.addWidget(b)
        form.addRow("Public Key:", h)

        self.kg_priv = QLineEdit(); self.kg_priv.setPlaceholderText("priv.pem")
        b2 = QPushButton("Browse..."); b2.clicked.connect(lambda: self._browse_save(self.kg_priv))
        h2 = QHBoxLayout(); h2.addWidget(self.kg_priv); h2.addWidget(b2)
        form.addRow("Private Key:", h2)

        btn = QPushButton("Generate Key Pair")
        btn.clicked.connect(self._do_keygen)
        layout.addLayout(form); layout.addWidget(btn); layout.addStretch()
        tab.setLayout(layout)
        return tab

    # --- Tab: Sign ---
    def _create_sign_tab(self):
        tab = QWidget(); layout = QVBoxLayout(); form = QFormLayout()
        self.s_algo = QComboBox()
        self.s_algo.addItems(["mldsa-44", "mldsa-65"])
        form.addRow("Algorithm:", self.s_algo)

        self.s_priv = QLineEdit(); self.s_priv.setPlaceholderText("priv.pem")
        b = QPushButton("Browse..."); b.clicked.connect(lambda: self._browse_open(self.s_priv))
        h = QHBoxLayout(); h.addWidget(self.s_priv); h.addWidget(b)
        form.addRow("Private Key:", h)

        self.s_input = QComboBox()
        self.s_input.addItems(["Text", "File"])
        self.s_input.currentTextChanged.connect(self._toggle_s_input)
        form.addRow("Input:", self.s_input)

        self.s_text = QTextEdit(); self.s_text.setPlaceholderText("Enter message..."); self.s_text.setMaximumHeight(100)
        form.addRow("Message:", self.s_text)

        self.s_file = QLineEdit(); self.s_file.setPlaceholderText("input.bin"); self.s_file.setVisible(False)
        b2 = QPushButton("Browse..."); b2.setVisible(False)
        b2.clicked.connect(lambda: self._browse_open(self.s_file))
        self._s_browse_btn = b2
        h2 = QHBoxLayout(); h2.addWidget(self.s_file); h2.addWidget(b2)
        form.addRow("Input File:", h2)

        self.s_out = QLineEdit(); self.s_out.setPlaceholderText("sig.bin")
        b3 = QPushButton("Browse..."); b3.clicked.connect(lambda: self._browse_save(self.s_out))
        h3 = QHBoxLayout(); h3.addWidget(self.s_out); h3.addWidget(b3)
        form.addRow("Output Sig:", h3)

        btn = QPushButton("Sign")
        btn.clicked.connect(self._do_sign)
        layout.addLayout(form); layout.addWidget(btn); layout.addStretch()
        tab.setLayout(layout)
        return tab

    def _toggle_s_input(self, mode):
        is_file = mode == "File"
        self.s_text.setVisible(not is_file)
        self.s_file.setVisible(is_file)
        if hasattr(self, '_s_browse_btn'):
            self._s_browse_btn.setVisible(is_file)

    # --- Tab: Verify ---
    def _create_verify_tab(self):
        tab = QWidget(); layout = QVBoxLayout(); form = QFormLayout()
        self.v_algo = QComboBox()
        self.v_algo.addItems(["mldsa-44", "mldsa-65"])
        form.addRow("Algorithm:", self.v_algo)

        self.v_pub = QLineEdit(); self.v_pub.setPlaceholderText("pub.pem")
        b = QPushButton("Browse..."); b.clicked.connect(lambda: self._browse_open(self.v_pub))
        h = QHBoxLayout(); h.addWidget(self.v_pub); h.addWidget(b)
        form.addRow("Public Key:", h)

        self.v_input = QComboBox()
        self.v_input.addItems(["Text", "File"])
        self.v_input.currentTextChanged.connect(self._toggle_v_input)
        form.addRow("Input:", self.v_input)

        self.v_text = QTextEdit(); self.v_text.setPlaceholderText("Enter original message..."); self.v_text.setMaximumHeight(100)
        form.addRow("Message:", self.v_text)

        self.v_file = QLineEdit(); self.v_file.setPlaceholderText("input.bin"); self.v_file.setVisible(False)
        b2 = QPushButton("Browse..."); b2.setVisible(False)
        b2.clicked.connect(lambda: self._browse_open(self.v_file))
        self._v_browse_btn = b2
        h2 = QHBoxLayout(); h2.addWidget(self.v_file); h2.addWidget(b2)
        form.addRow("Input File:", h2)

        self.v_sig = QLineEdit(); self.v_sig.setPlaceholderText("sig.bin")
        b3 = QPushButton("Browse..."); b3.clicked.connect(lambda: self._browse_open(self.v_sig))
        h3 = QHBoxLayout(); h3.addWidget(self.v_sig); h3.addWidget(b3)
        form.addRow("Sig File:", h3)

        btn = QPushButton("Verify")
        btn.clicked.connect(self._do_verify)
        layout.addLayout(form); layout.addWidget(btn); layout.addStretch()
        tab.setLayout(layout)
        return tab

    def _toggle_v_input(self, mode):
        is_file = mode == "File"
        self.v_text.setVisible(not is_file)
        self.v_file.setVisible(is_file)
        if hasattr(self, '_v_browse_btn'):
            self._v_browse_btn.setVisible(is_file)

    # --- Tab: KEM ---
    def _create_kem_tab(self):
        tab = QWidget(); layout = QVBoxLayout(); form = QFormLayout()
        self.k_algo = QComboBox()
        self.k_algo.addItems(["mlkem-512"])
        form.addRow("Algorithm:", self.k_algo)

        self.k_pub = QLineEdit(); self.k_pub.setPlaceholderText("kem_pub.pem")
        b = QPushButton("Browse..."); b.clicked.connect(lambda: self._browse_open(self.k_pub))
        h = QHBoxLayout(); h.addWidget(self.k_pub); h.addWidget(b)
        form.addRow("Public Key:", h)

        self.k_priv = QLineEdit(); self.k_priv.setPlaceholderText("kem_priv.pem")
        b2 = QPushButton("Browse..."); b2.clicked.connect(lambda: self._browse_open(self.k_priv))
        h2 = QHBoxLayout(); h2.addWidget(self.k_priv); h2.addWidget(b2)
        form.addRow("Private Key:", h2)

        self.k_ct = QLineEdit(); self.k_ct.setPlaceholderText("ct.bin")
        b3 = QPushButton("Browse..."); b3.clicked.connect(lambda: self._browse_save(self.k_ct))
        h3 = QHBoxLayout(); h3.addWidget(self.k_ct); h3.addWidget(b3)
        form.addRow("Ciphertext:", h3)

        self.k_ss = QLineEdit(); self.k_ss.setPlaceholderText("ss.bin")
        b4 = QPushButton("Browse..."); b4.clicked.connect(lambda: self._browse_save(self.k_ss))
        h4 = QHBoxLayout(); h4.addWidget(self.k_ss); h4.addWidget(b4)
        form.addRow("Shared Secret:", h4)

        btn_enc = QPushButton("Encapsulate")
        btn_enc.clicked.connect(self._do_encaps)
        btn_dec = QPushButton("Decapsulate")
        btn_dec.clicked.connect(self._do_decaps)

        layout.addLayout(form)
        bh = QHBoxLayout(); bh.addWidget(btn_enc); bh.addWidget(btn_dec)
        layout.addLayout(bh); layout.addStretch()
        tab.setLayout(layout)
        return tab

    # --- Tab: Certificate ---
    def _create_cert_tab(self):
        tab = QWidget(); layout = QVBoxLayout(); form = QFormLayout()

        self.c_ca_priv = QLineEdit(); self.c_ca_priv.setPlaceholderText("ca_priv.pem")
        b = QPushButton("Browse..."); b.clicked.connect(lambda: self._browse_open(self.c_ca_priv))
        h = QHBoxLayout(); h.addWidget(self.c_ca_priv); h.addWidget(b)
        form.addRow("CA Private Key:", h)

        self.c_sub_pub = QLineEdit(); self.c_sub_pub.setPlaceholderText("subject_pub.pem")
        b2 = QPushButton("Browse..."); b2.clicked.connect(lambda: self._browse_open(self.c_sub_pub))
        h2 = QHBoxLayout(); h2.addWidget(self.c_sub_pub); h2.addWidget(b2)
        form.addRow("Subject Public Key:", h2)

        self.c_sub_name = QLineEdit(); self.c_sub_name.setPlaceholderText("Alice")
        form.addRow("Subject Name:", self.c_sub_name)

        self.c_out = QLineEdit(); self.c_out.setPlaceholderText("cert.json")
        b3 = QPushButton("Browse..."); b3.clicked.connect(lambda: self._browse_save(self.c_out))
        h3 = QHBoxLayout(); h3.addWidget(self.c_out); h3.addWidget(b3)
        form.addRow("Certificate:", h3)

        self.c_ca_pub = QLineEdit(); self.c_ca_pub.setPlaceholderText("ca_pub.pem")
        b4 = QPushButton("Browse..."); b4.clicked.connect(lambda: self._browse_open(self.c_ca_pub))
        h4 = QHBoxLayout(); h4.addWidget(self.c_ca_pub); h4.addWidget(b4)
        form.addRow("CA Public Key:", h4)

        self.c_cert_in = QLineEdit(); self.c_cert_in.setPlaceholderText("cert.json")
        b5 = QPushButton("Browse..."); b5.clicked.connect(lambda: self._browse_open(self.c_cert_in))
        h5 = QHBoxLayout(); h5.addWidget(self.c_cert_in); h5.addWidget(b5)
        form.addRow("Cert to Verify:", h5)

        btn_sign = QPushButton("Sign Certificate")
        btn_sign.clicked.connect(self._do_cert_sign)
        btn_verify = QPushButton("Verify Certificate")
        btn_verify.clicked.connect(self._do_cert_verify)

        layout.addLayout(form)
        bh = QHBoxLayout(); bh.addWidget(btn_sign); bh.addWidget(btn_verify)
        layout.addLayout(bh); layout.addStretch()
        tab.setLayout(layout)
        return tab

    # --- Tab: Tests ---
    def _create_tests_tab(self):
        tab = QWidget(); layout = QVBoxLayout()
        btn_tests = QPushButton("Run Unit Tests")
        btn_tests.clicked.connect(self._do_tests)
        btn_kat = QPushButton("Run KAT Validation")
        btn_kat.clicked.connect(self._do_kat)
        layout.addWidget(btn_tests); layout.addWidget(btn_kat)
        form = QFormLayout()
        self.kat_file = QLineEdit()
        self.kat_file.setPlaceholderText("test_vectors/pq_kats.json")
        bk = QPushButton("Browse..."); bk.clicked.connect(lambda: self._browse_open(self.kat_file))
        h = QHBoxLayout(); h.addWidget(self.kat_file); h.addWidget(bk)
        form.addRow("KAT Vectors:", h)
        layout.addLayout(form); layout.addStretch()
        tab.setLayout(layout)
        return tab

    # --- Tab: Benchmark ---
    def _create_benchmark_tab(self):
        tab = QWidget(); layout = QVBoxLayout()
        group = QGroupBox("Benchmark Configuration")
        gl = QFormLayout()
        self.bm_iter = QSpinBox()
        self.bm_iter.setRange(5, 200); self.bm_iter.setValue(30)
        gl.addRow("Iterations:", self.bm_iter)
        self.bm_threads = QSpinBox()
        self.bm_threads.setRange(1, 64); self.bm_threads.setValue(1)
        self.bm_threads.setSpecialValueText("Auto")
        gl.addRow("Threads:", self.bm_threads)
        group.setLayout(gl)
        layout.addWidget(group)
        self.bm_btn = QPushButton("Run Full Benchmark (may take several minutes)")
        self.bm_btn.clicked.connect(self._do_benchmark)
        layout.addWidget(self.bm_btn)
        info = QTextEdit()
        info.setReadOnly(True); info.setMaximumHeight(65)
        info.setPlainText("Benchmarks ML-DSA-44, ML-DSA-65, ML-KEM-512.\n"
                          "Results include mean, median, std dev, 95% CI.\n"
                          "Temp files cleaned up automatically.")
        layout.addWidget(info); layout.addStretch()
        tab.setLayout(layout)
        return tab

    # --- Actions ---

    def _do_keygen(self):
        if not self.engine:
            QMessageBox.warning(self, "No DLL", "DLL not loaded. Build the project first.")
            return
        algo = self.kg_algo.currentText()
        pub = self.kg_pub.text().strip()
        priv = self.kg_priv.text().strip()
        if not pub or not priv:
            QMessageBox.warning(self, "Input Error", "Public and private key files required.")
            return
        self.log(f"Generating {algo} key pair...")
        try:
            self.engine.keygen(algo, pub, priv)
            self.log("[OK] Key pair generated successfully.")
        except Exception as e:
            self.log(f"[ERROR] {e}")

    def _do_sign(self):
        if not self.engine:
            QMessageBox.warning(self, "No DLL", "DLL not loaded. Build the project first.")
            return
        algo = self.s_algo.currentText()
        priv = self.s_priv.text().strip()
        out = self.s_out.text().strip()
        if not priv:
            QMessageBox.warning(self, "Input Error", "Private key required.")
            return
        is_file = self.s_input.currentText() == "File"
        self.log(f"Signing with {algo}...")
        try:
            if is_file:
                in_file = self.s_file.text().strip()
                if not in_file:
                    QMessageBox.warning(self, "Error", "Input file required.")
                    return
                result = self.engine.sign(algo, "sha256", priv, open(in_file, 'rb').read(), out, 1)
            else:
                text = self.s_text.toPlainText()
                if not text:
                    QMessageBox.warning(self, "Error", "Message required.")
                    return
                result = self.engine.sign(algo, "sha256", priv, text.encode('utf-8'), out, 1)
            if out:
                self.log(f"[OK] Signature saved to: {out}")
            else:
                self.log("[OK] Signature generated:")
            self.log(f"Signature (hex): {result[:128]}...")
        except Exception as e:
            self.log(f"[ERROR] {e}")

    def _do_verify(self):
        if not self.engine:
            QMessageBox.warning(self, "No DLL", "DLL not loaded. Build the project first.")
            return
        algo = self.v_algo.currentText()
        pub = self.v_pub.text().strip()
        sig_file = self.v_sig.text().strip()
        if not pub or not sig_file:
            QMessageBox.warning(self, "Error", "Public key and sig file required.")
            return
        is_file = self.v_input.currentText() == "File"
        self.log(f"Verifying with {algo}...")
        try:
            if is_file:
                in_file = self.v_file.text().strip()
                if not in_file:
                    QMessageBox.warning(self, "Error", "Input file required.")
                    return
                msg = open(in_file, 'rb').read()
            else:
                msg = self.v_text.toPlainText().encode('utf-8')
            valid = self.engine.verify(algo, "sha256", pub, msg, sig_file)
            if valid:
                self.log("[PASS] Signature VALID!")
                QMessageBox.information(self, "Verify", "Signature VALID!")
            else:
                self.log("[FAIL] Signature INVALID!")
                QMessageBox.warning(self, "Verify", "Signature INVALID!")
        except Exception as e:
            self.log(f"[ERROR] {e}")

    def _do_encaps(self):
        if not self.engine:
            QMessageBox.warning(self, "No DLL", "DLL not loaded.")
            return
        algo = self.k_algo.currentText()
        pub = self.k_pub.text().strip()
        ct = self.k_ct.text().strip()
        ss = self.k_ss.text().strip()
        if not pub or not ct or not ss:
            QMessageBox.warning(self, "Error", "Public key, ct, and ss files required.")
            return
        self.log(f"Encapsulating with {algo}...")
        try:
            result = self.engine.encaps(algo, pub, ct, ss)
            self.log(f"[OK] Ciphertext: {ct}")
            self.log(f"[OK] Shared secret: {ss}")
        except Exception as e:
            self.log(f"[ERROR] {e}")

    def _do_decaps(self):
        if not self.engine:
            QMessageBox.warning(self, "No DLL", "DLL not loaded.")
            return
        algo = self.k_algo.currentText()
        priv = self.k_priv.text().strip()
        ct = self.k_ct.text().strip()
        ss = self.k_ss.text().strip()
        if not priv or not ct or not ss:
            QMessageBox.warning(self, "Error", "Private key, ct, and ss files required.")
            return
        self.log(f"Decapsulating with {algo}...")
        try:
            ok = self.engine.decaps(algo, priv, ct, ss)
            if ok:
                self.log(f"[OK] Decapsulation complete. Shared secret: {ss}")
            else:
                self.log("[FAIL] Decapsulation failed.")
        except Exception as e:
            self.log(f"[ERROR] {e}")

    def _do_cert_sign(self):
        if not self.pqtool_exe:
            QMessageBox.warning(self, "Not Found", "pqtool.exe not found.")
            return
        ca_priv = self.c_ca_priv.text().strip()
        sub_pub = self.c_sub_pub.text().strip()
        subject = self.c_sub_name.text().strip()
        out = self.c_out.text().strip()
        if not ca_priv or not sub_pub or not subject or not out:
            QMessageBox.warning(self, "Error", "All fields required for cert sign.")
            return
        self.log("Signing PQ certificate...")
        result = _run_in_temp(self.pqtool_exe, ["cert", "--ca-priv", ca_priv, "--subject-pub", sub_pub,
                                                  "--subject", subject, "--out", out], timeout=30)
        self.log(result)

    def _do_cert_verify(self):
        if not self.pqtool_exe:
            QMessageBox.warning(self, "Not Found", "pqtool.exe not found.")
            return
        ca_pub = self.c_ca_pub.text().strip()
        cert_file = self.c_cert_in.text().strip()
        if not ca_pub or not cert_file:
            QMessageBox.warning(self, "Error", "CA public key and cert file required.")
            return
        self.log("Verifying PQ certificate...")
        result = _run_in_temp(self.pqtool_exe, ["cert", "--ca-pub", ca_pub, "--in", cert_file], timeout=30)
        self.log(result)

    def _do_tests(self):
        exe = _find_exe("catch2_test.exe")
        if not exe:
            self.log("catch2_test.exe not found.")
            return
        self.log("Running unit tests in background...")
        self._test_worker = WorkerThread(lambda: _run_in_temp(exe, [], timeout=300))
        self._test_worker.finished.connect(self._on_tests_done)
        self._test_worker.start()

    def _on_tests_done(self, msg):
        self.log(msg)
        self._test_worker = None

    def _do_kat(self):
        kat_path = self.kat_file.text().strip()
        if not kat_path:
            QMessageBox.warning(self, "Error", "KAT vectors file required.")
            return
        if not os.path.exists(kat_path):
            QMessageBox.warning(self, "Error", f"File not found: {kat_path}")
            return
        self.log(f"Running KAT from: {kat_path}")
        if self.engine:
            result = self.engine.run_kat(kat_path)
            if "Full KAT validation requires CLI" not in result:
                self.log(result)
                return
        exe = self.pqtool_exe
        if not exe:
            self.log("pqtool.exe not found.")
            return
        self.log("Running KAT via CLI subprocess...")
        self._kat_worker = WorkerThread(lambda: _run_in_temp(exe, ["--kat", kat_path], timeout=600))
        self._kat_worker.finished.connect(self._on_kat_done)
        self._kat_worker.start()

    def _on_kat_done(self, msg):
        self.log(msg)
        self._kat_worker = None

    def _do_benchmark(self):
        if not self.benchmark_exe:
            QMessageBox.warning(self, "Not Found", "benchmark.exe not found.")
            return
        iters = self.bm_iter.value()
        threads = self.bm_threads.value()
        self.log(f"Starting benchmark ({iters} iterations, {threads} threads)...")
        self.log("Running in background...")
        self.bm_btn.setEnabled(False)
        self.bm_btn.setText("Benchmark running...")
        args = ["--iterations", str(iters)]
        if threads > 0:
            args += ["--threads", str(threads)]
        self._bench_worker = WorkerThread(lambda: _run_in_temp(self.benchmark_exe, args, timeout=600))
        self._bench_worker.finished.connect(self._on_benchmark_done)
        self._bench_worker.start()

    def _on_benchmark_done(self, msg):
        self.log(msg)
        self.bm_btn.setEnabled(True)
        self.bm_btn.setText("Run Full Benchmark")
        self._bench_worker = None


# =============================================================================
# Entry Point
# =============================================================================
def main():
    app = QApplication(sys.argv)
    dll_path = _find_dll()
    engine = None
    if dll_path:
        try:
            engine = PQEngine(dll_path)
            print(f"[INFO] Loaded DLL: {dll_path}")
        except Exception as e:
            print(f"[WARN] Failed to load DLL: {e}")
    if not engine:
        print("[INFO] No DLL found. GUI will use CLI subprocess mode.")
    window = Lab6Window(engine, dll_path)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
