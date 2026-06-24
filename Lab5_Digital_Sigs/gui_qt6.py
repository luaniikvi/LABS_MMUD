#!/usr/bin/env python3
"""Lab 5 Digital Signatures (ECDSA, RSA-PSS) GUI - DLL + subprocess mode"""

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
class SigEngine:
    """Wrapper around sigtool.dll using ctypes."""

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

        self.dll.lab5_keygen.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.dll.lab5_keygen.restype = ctypes.c_int

        self.dll.lab5_sign.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_int, ctypes.c_char_p
        ]
        self.dll.lab5_sign.restype = ctypes.c_char_p

        self.dll.lab5_verify.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_char_p
        ]
        self.dll.lab5_verify.restype = ctypes.c_int

        self.dll.lab5_sign_file.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
            ctypes.c_char_p
        ]
        self.dll.lab5_sign_file.restype = ctypes.c_char_p

        self.dll.lab5_verify_file.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        self.dll.lab5_verify_file.restype = ctypes.c_int

        self.dll.lab5_run_tests.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
                                            ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]
        self.dll.lab5_run_tests.restype = ctypes.c_char_p

        self.dll.lab5_run_kat.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.dll.lab5_run_kat.restype = ctypes.c_char_p

    def keygen(self, algo, pub_file, priv_file):
        error_buf = ctypes.create_string_buffer(1024)
        rc = self.dll.lab5_keygen(algo.encode(), pub_file.encode(), priv_file.encode(), error_buf)
        if rc != 0:
            raise RuntimeError(error_buf.value.decode())
        return True

    def sign(self, algo, hash_algo, priv_key_file, message_bytes, output_file, encode_mode=0):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab5_sign(
            algo.encode(), hash_algo.encode(), priv_key_file.encode(),
            message_bytes, len(message_bytes),
            output_file.encode() if output_file else b'',
            encode_mode, error_buf
        )
        if not result:
            raise RuntimeError(error_buf.value.decode())
        return result.decode() if result else ""

    def sign_file(self, algo, hash_algo, priv_key_file, input_file, output_file, encode_mode=0):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab5_sign_file(
            algo.encode(), hash_algo.encode(), priv_key_file.encode(),
            input_file.encode(), output_file.encode() if output_file else b'',
            encode_mode, error_buf
        )
        if not result:
            raise RuntimeError(error_buf.value.decode())
        return result.decode() if result else ""

    def verify(self, algo, hash_algo, pub_key_file, message_bytes, sig_file):
        error_buf = ctypes.create_string_buffer(1024)
        rc = self.dll.lab5_verify(
            algo.encode(), hash_algo.encode(), pub_key_file.encode(),
            message_bytes, len(message_bytes),
            sig_file.encode(), error_buf
        )
        if rc < 0:
            raise RuntimeError(error_buf.value.decode())
        return bool(rc)

    def verify_file(self, algo, hash_algo, pub_key_file, input_file, sig_file):
        error_buf = ctypes.create_string_buffer(1024)
        rc = self.dll.lab5_verify_file(
            algo.encode(), hash_algo.encode(), pub_key_file.encode(),
            input_file.encode(), sig_file.encode(), error_buf
        )
        if rc < 0:
            raise RuntimeError(error_buf.value.decode())
        return bool(rc)

    def run_tests(self):
        total = ctypes.c_int(0)
        passed = ctypes.c_int(0)
        failed = ctypes.c_int(0)
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab5_run_tests(ctypes.byref(total), ctypes.byref(passed),
                                          ctypes.byref(failed), error_buf)
        if not result:
            return f"ERROR: {error_buf.value.decode()}"
        return result.decode()

    def run_kat(self, vectors_file):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab5_run_kat(vectors_file.encode(), error_buf)
        if not result:
            return f"ERROR: {error_buf.value.decode()}"
        return result.decode()


# =============================================================================
# Worker Thread for Long Operations (keeps GUI responsive)
# =============================================================================
class WorkerThread(QThread):
    finished = pyqtSignal(str)

    def __init__(self, target_func):
        super().__init__()
        self.target_func = target_func

    def run(self):
        """Run the target function on a background thread."""
        try:
            result = self.target_func()
            self.finished.emit(str(result))
        except Exception as e:
            self.finished.emit(f"ERROR: {str(e)}")


# =============================================================================
# Subprocess Helpers
# =============================================================================
def _find_exe(exe_name):
    """Find the sigtool or benchmark executable relative to the script dir."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "build", "Release", exe_name),
        os.path.join(script_dir, "build", exe_name),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def _run_subprocess_in_temp(exe, args, timeout=600):
    """Run an executable in a temp directory and return its output.
    All temp files created by the subprocess are cleaned up automatically."""
    cwd = tempfile.mkdtemp(prefix="lab5_")
    try:
        result = subprocess.run(
            [exe] + args,
            capture_output=True, text=True, cwd=cwd,
            timeout=timeout
        )
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        return output
    except subprocess.TimeoutExpired:
        return "[ERROR] Process timed out."
    except Exception as e:
        return f"[ERROR] {e}"
    finally:
        shutil.rmtree(cwd, ignore_errors=True)


# =============================================================================
# DLL auto-discovery
# =============================================================================
def _find_dll():
    """Search standard build paths for sigtool.dll and return path or None."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    search_paths = [
        os.path.join(script_dir, "build", "Release", "sigtool.dll"),
        os.path.join(script_dir, "build", "sigtool.dll"),
    ]
    for p in search_paths:
        if os.path.exists(p):
            return p
    return None


# =============================================================================
# Main GUI Window
# =============================================================================
class Lab5Window(QWidget):
    def __init__(self, engine=None, dll_path=None):
        super().__init__()
        self.engine = engine
        self.dll_path = dll_path
        self.sigtool_exe_path = _find_exe("sigtool.exe")
        self.benchmark_exe_path = _find_exe("benchmark.exe")
        self._worker = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Lab 5 — Digital Signatures (ECDSA, RSA-PSS)")
        self.setMinimumSize(950, 750)

        main_layout = QVBoxLayout()
        tabs = QTabWidget()

        keygen_tab = self._create_keygen_tab()
        tabs.addTab(keygen_tab, "Key Generation")

        sign_tab = self._create_sign_tab()
        tabs.addTab(sign_tab, "Sign")

        verify_tab = self._create_verify_tab()
        tabs.addTab(verify_tab, "Verify")

        tests_tab = self._create_tests_tab()
        tabs.addTab(tests_tab, "Tests")

        bench_tab = self._create_benchmark_tab()
        tabs.addTab(bench_tab, "Benchmark")

        # DLL toolbar
        status_layout = QHBoxLayout()
        dll_label = QLabel("DLL:")
        self.dll_path_edit = QLineEdit()
        self.dll_path_edit.setReadOnly(True)
        if self.dll_path:
            self.dll_path_edit.setText(self.dll_path)
        self.dll_path_edit.setPlaceholderText("No DLL loaded — will use CLI subprocess")

        btn_load_dll = QPushButton("Load")
        btn_load_dll.setToolTip("Auto-detect and load sigtool.dll from build paths")
        btn_load_dll.clicked.connect(self._load_dll)

        btn_browse_dll = QPushButton("Browse...")
        btn_browse_dll.setToolTip("Manually select sigtool.dll file")
        btn_browse_dll.clicked.connect(self._browse_dll)

        status_layout.addWidget(dll_label)
        status_layout.addWidget(self.dll_path_edit, 1)
        status_layout.addWidget(btn_load_dll)
        status_layout.addWidget(btn_browse_dll)

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
        """Auto-detect and load sigtool.dll from standard build paths."""
        path = _find_dll()
        if not path:
            QMessageBox.warning(self, "Not Found", "sigtool.dll not found in build directories.\nBuild the project first or use Browse.")
            return
        try:
            self.engine = SigEngine(path)
            self.dll_path = path
            self.dll_path_edit.setText(path)
            self.log(f"[INFO] Loaded DLL: {path}")
        except Exception as e:
            QMessageBox.warning(self, "DLL Error", f"Failed to load DLL:\n{e}")

    def _browse_dll(self):
        """Open file dialog to select sigtool.dll and reload engine."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select sigtool.dll", "",
            "DLL files (*.dll);;All files (*)"
        )
        if not path:
            return
        try:
            self.engine = SigEngine(path)
            self.dll_path = path
            self.dll_path_edit.setText(path)
            self.log(f"[INFO] Loaded DLL: {path}")
        except Exception as e:
            QMessageBox.warning(self, "DLL Error", f"Failed to load DLL:\n{e}")

    def _browse_open(self, widget):
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path:
            widget.setText(path)

    def _browse_save(self, widget):
        path, _ = QFileDialog.getSaveFileName(self, "Save file")
        if path:
            widget.setText(path)

    # --- Tab Builders ---

    def _create_keygen_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        form = QFormLayout()

        self.kg_algo = QComboBox()
        self.kg_algo.addItems(["ecdsa-p256", "ecdsa-p384", "rsa-pss-3072"])
        form.addRow("Algorithm:", self.kg_algo)

        self.kg_pub = QLineEdit(); self.kg_pub.setPlaceholderText("pub.pem")
        btn_pub = QPushButton("Browse...")
        btn_pub.clicked.connect(lambda: self._browse_save(self.kg_pub))
        h = QHBoxLayout(); h.addWidget(self.kg_pub); h.addWidget(btn_pub)
        form.addRow("Public Key:", h)

        self.kg_priv = QLineEdit(); self.kg_priv.setPlaceholderText("priv.pem")
        btn_priv = QPushButton("Browse...")
        btn_priv.clicked.connect(lambda: self._browse_save(self.kg_priv))
        h = QHBoxLayout(); h.addWidget(self.kg_priv); h.addWidget(btn_priv)
        form.addRow("Private Key:", h)

        btn = QPushButton("Generate Key Pair")
        btn.clicked.connect(self._do_keygen)

        layout.addLayout(form)
        layout.addWidget(btn)
        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def _create_sign_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        form = QFormLayout()

        self.s_algo = QComboBox()
        self.s_algo.addItems(["ecdsa-p256", "ecdsa-p384", "rsa-pss-3072"])
        form.addRow("Algorithm:", self.s_algo)

        self.s_hash = QComboBox()
        self.s_hash.addItems(["sha256", "sha384"])
        form.addRow("Hash:", self.s_hash)

        self.s_priv = QLineEdit(); self.s_priv.setPlaceholderText("priv.pem")
        btn = QPushButton("Browse...")
        btn.clicked.connect(lambda: self._browse_open(self.s_priv))
        h = QHBoxLayout(); h.addWidget(self.s_priv); h.addWidget(btn)
        form.addRow("Private Key:", h)

        self.s_input_mode = QComboBox()
        self.s_input_mode.addItems(["Text", "File"])
        self.s_input_mode.currentTextChanged.connect(self._toggle_sign_input)
        form.addRow("Input Mode:", self.s_input_mode)

        self.s_text = QTextEdit(); self.s_text.setPlaceholderText("Enter message to sign...")
        self.s_text.setMaximumHeight(100)
        form.addRow("Message:", self.s_text)

        self.s_file = QLineEdit(); self.s_file.setPlaceholderText("input.bin")
        self.s_file.setVisible(False)
        btn2 = QPushButton("Browse...")
        btn2.setVisible(False)
        btn2.clicked.connect(lambda: self._browse_open(self.s_file))
        self._s_browse_btn = btn2
        h2 = QHBoxLayout(); h2.addWidget(self.s_file); h2.addWidget(btn2)
        form.addRow("Input File:", h2)

        self.s_out = QLineEdit(); self.s_out.setPlaceholderText("sig.der")
        btn3 = QPushButton("Browse...")
        btn3.clicked.connect(lambda: self._browse_save(self.s_out))
        h3 = QHBoxLayout(); h3.addWidget(self.s_out); h3.addWidget(btn3)
        form.addRow("Output Sig:", h3)

        btn_sign = QPushButton("Sign")
        btn_sign.clicked.connect(self._do_sign)

        layout.addLayout(form)
        layout.addWidget(btn_sign)
        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def _create_verify_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        form = QFormLayout()

        self.v_algo = QComboBox()
        self.v_algo.addItems(["ecdsa-p256", "ecdsa-p384", "rsa-pss-3072"])
        form.addRow("Algorithm:", self.v_algo)

        self.v_hash = QComboBox()
        self.v_hash.addItems(["sha256", "sha384"])
        form.addRow("Hash:", self.v_hash)

        self.v_pub = QLineEdit(); self.v_pub.setPlaceholderText("pub.pem")
        btn = QPushButton("Browse...")
        btn.clicked.connect(lambda: self._browse_open(self.v_pub))
        h = QHBoxLayout(); h.addWidget(self.v_pub); h.addWidget(btn)
        form.addRow("Public Key:", h)

        self.v_input_mode = QComboBox()
        self.v_input_mode.addItems(["Text", "File"])
        self.v_input_mode.currentTextChanged.connect(self._toggle_verify_input)
        form.addRow("Input Mode:", self.v_input_mode)

        self.v_text = QTextEdit(); self.v_text.setPlaceholderText("Enter original message...")
        self.v_text.setMaximumHeight(100)
        form.addRow("Message:", self.v_text)

        self.v_file = QLineEdit(); self.v_file.setPlaceholderText("input.bin")
        self.v_file.setVisible(False)
        btn2 = QPushButton("Browse...")
        btn2.setVisible(False)
        btn2.clicked.connect(lambda: self._browse_open(self.v_file))
        self._v_browse_btn = btn2
        h2 = QHBoxLayout(); h2.addWidget(self.v_file); h2.addWidget(btn2)
        form.addRow("Input File:", h2)

        self.v_sig = QLineEdit(); self.v_sig.setPlaceholderText("sig.der")
        btn3 = QPushButton("Browse...")
        btn3.clicked.connect(lambda: self._browse_open(self.v_sig))
        h3 = QHBoxLayout(); h3.addWidget(self.v_sig); h3.addWidget(btn3)
        form.addRow("Sig File:", h3)

        btn_v = QPushButton("Verify Signature")
        btn_v.clicked.connect(self._do_verify)

        layout.addLayout(form)
        layout.addWidget(btn_v)
        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def _create_tests_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        btn_tests = QPushButton("Run Unit Tests")
        btn_tests.clicked.connect(self._do_tests)

        btn_kat = QPushButton("Run KAT Validation")
        btn_kat.clicked.connect(self._do_kat)

        layout.addWidget(btn_tests)
        layout.addWidget(btn_kat)

        form = QFormLayout()
        self.kat_file = QLineEdit()
        self.kat_file.setPlaceholderText("test_vectors/sig_kats.json")
        btn_kat_file = QPushButton("Browse...")
        btn_kat_file.clicked.connect(lambda: self._browse_open(self.kat_file))
        h = QHBoxLayout(); h.addWidget(self.kat_file); h.addWidget(btn_kat_file)
        form.addRow("KAT Vectors:", h)
        layout.addLayout(form)

        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def _create_benchmark_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        group = QGroupBox("Benchmark Configuration")
        glayout = QFormLayout()

        self.bm_iterations = QSpinBox()
        self.bm_iterations.setRange(5, 200)
        self.bm_iterations.setValue(30)
        glayout.addRow("Iterations:", self.bm_iterations)

        self.bm_threads = QSpinBox()
        self.bm_threads.setRange(1, 64)
        self.bm_threads.setValue(1)
        self.bm_threads.setSpecialValueText("Auto")
        glayout.addRow("Threads:", self.bm_threads)

        group.setLayout(glayout)
        layout.addWidget(group)

        self.bm_btn = QPushButton("Run Full Benchmark (may take several minutes)")
        self.bm_btn.clicked.connect(self._do_benchmark)
        layout.addWidget(self.bm_btn)

        info = QTextEdit()
        info.setReadOnly(True)
        info.setMaximumHeight(105)
        info.setPlainText(
            "This benchmark runs ECDSA P-256, ECDSA P-384, and RSA-PSS-3072 "
            "key generation, signing, and verification tests.\n\n"
            "Results include mean, median, std deviation, and 95% confidence "
            "intervals for each operation.\n\n"
            "RSA key generation is significantly slower than ECDSA — expect "
            "several minutes to complete."
        )
        layout.addWidget(info)

        layout.addStretch()
        tab.setLayout(layout)
        return tab

    # --- UI Toggles ---

    def _toggle_sign_input(self, mode):
        is_file = mode == "File"
        self.s_text.setVisible(not is_file)
        self.s_file.setVisible(is_file)
        if hasattr(self, '_s_browse_btn'):
            self._s_browse_btn.setVisible(is_file)

    def _toggle_verify_input(self, mode):
        is_file = mode == "File"
        self.v_text.setVisible(not is_file)
        self.v_file.setVisible(is_file)
        if hasattr(self, '_v_browse_btn'):
            self._v_browse_btn.setVisible(is_file)

    # --- Actions ---

    def _do_keygen(self):
        if not self.engine:
            QMessageBox.warning(self, "No DLL", "DLL not loaded. Build the project first.")
            return
        algo = self.kg_algo.currentText()
        pub = self.kg_pub.text().strip()
        priv = self.kg_priv.text().strip()
        if not pub or not priv:
            QMessageBox.warning(self, "Input Error", "Public and private key files are required.")
            return
        self.log(f"Generating {algo} key pair...")
        self.log(f"  Public:  {pub}")
        self.log(f"  Private: {priv}")
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
        hash_algo = self.s_hash.currentText()
        priv = self.s_priv.text().strip()
        out = self.s_out.text().strip()

        if not priv:
            QMessageBox.warning(self, "Input Error", "Private key is required.")
            return

        is_file = self.s_input_mode.currentText() == "File"
        self.log(f"Signing with {algo} ({hash_algo})...")
        try:
            if is_file:
                in_file = self.s_file.text().strip()
                if not in_file:
                    QMessageBox.warning(self, "Input Error", "Input file required.")
                    return
                result = self.engine.sign_file(algo, hash_algo, priv, in_file, out, 1)
                if out:
                    self.log(f"[OK] Signature saved to: {out}")
                else:
                    self.log("[OK] Signature generated (not saved to file):")
                self.log(f"Signature (hex): {result[:128]}...")
            else:
                text = self.s_text.toPlainText()
                if not text:
                    QMessageBox.warning(self, "Input Error", "Message text required.")
                    return
                result = self.engine.sign(algo, hash_algo, priv, text.encode('utf-8'), out, 1)
                if out:
                    self.log(f"[OK] Signature saved to: {out}")
                else:
                    self.log("[OK] Signature generated (not saved to file):")
                self.log(f"Signature (hex): {result[:128]}...")
        except Exception as e:
            self.log(f"[ERROR] {e}")

    def _do_verify(self):
        if not self.engine:
            QMessageBox.warning(self, "No DLL", "DLL not loaded. Build the project first.")
            return
        algo = self.v_algo.currentText()
        hash_algo = self.v_hash.currentText()
        pub = self.v_pub.text().strip()
        sig_file = self.v_sig.text().strip()
        if not pub or not sig_file:
            QMessageBox.warning(self, "Input Error", "Public key and sig file are required.")
            return
        is_file = self.v_input_mode.currentText() == "File"
        self.log(f"Verifying with {algo} ({hash_algo})...")
        try:
            if is_file:
                in_file = self.v_file.text().strip()
                if not in_file:
                    QMessageBox.warning(self, "Input Error", "Input file required.")
                    return
                valid = self.engine.verify_file(algo, hash_algo, pub, in_file, sig_file)
            else:
                text = self.v_text.toPlainText()
                if not text:
                    QMessageBox.warning(self, "Input Error", "Message text required.")
                    return
                valid = self.engine.verify(algo, hash_algo, pub, text.encode('utf-8'), sig_file)
            if valid:
                self.log("[PASS] Signature is VALID!")
                QMessageBox.information(self, "Verification", "Signature is VALID!")
            else:
                self.log("[FAIL] Signature is INVALID!")
                QMessageBox.warning(self, "Verification", "Signature is INVALID!")
        except Exception as e:
            self.log(f"[ERROR] {e}")

    def _do_tests(self):
        """Run unit tests via catch2_test.exe subprocess in background thread."""
        exe = _find_exe("catch2_test.exe")
        if not exe:
            self.log("catch2_test.exe not found. Build the project first.")
            return

        self.log("Running unit tests in background...")
        self.log("(GUI stays responsive while tests run)")
        self.log("")

        self._test_worker = WorkerThread(lambda: _run_subprocess_in_temp(exe, [], timeout=300))
        self._test_worker.finished.connect(self._on_tests_done)
        self._test_worker.start()

    def _on_tests_done(self, msg):
        self.log(msg)
        self._test_worker = None

    def _do_kat(self):
        """Run KAT validation in a background thread so GUI doesn't freeze."""
        kat_path = self.kat_file.text().strip()
        if not kat_path:
            QMessageBox.warning(self, "Input Error", "KAT vectors file required.")
            return
        if not os.path.exists(kat_path):
            QMessageBox.warning(self, "File Error", f"File not found: {kat_path}")
            return

        if self.engine:
            result = self.engine.run_kat(kat_path)
            placeholder_markers = ["Full KAT validation requires CLI", "requires CLI: sigtool --kat"]
            if not any(m in result for m in placeholder_markers):
                self.log(result)
                return

        self.log("Running KAT validation in background...")
        self.log("(GUI will stay responsive while it runs)")

        exe = self.sigtool_exe_path
        if not exe:
            self.log("[ERROR] sigtool.exe not found.")
            return

        args = ["--kat", kat_path]

        def run_kat():
            return _run_subprocess_in_temp(exe, args, timeout=600)

        self._worker = WorkerThread(run_kat)
        self._worker.finished.connect(lambda msg: self.log(msg))
        self._worker.start()

    def _do_benchmark(self):
        """Run benchmark in a background thread so GUI doesn't freeze."""
        if not self.benchmark_exe_path:
            QMessageBox.warning(self, "Not Found", "benchmark.exe not found. Build the project first.")
            return

        iterations = self.bm_iterations.value()
        threads = self.bm_threads.value()

        self.log(f"Starting benchmark ({iterations} iterations, {threads} threads)...")
        self.log("Running in background — GUI stays responsive.")
        self.log("This may take several minutes. Please wait...")
        self.log("")

        self.bm_btn.setEnabled(False)
        self.bm_btn.setText("Benchmark running...")

        args = ["--iterations", str(iterations)]
        if threads > 0:
            args += ["--threads", str(threads)]

        def run_bench():
            return _run_subprocess_in_temp(self.benchmark_exe_path, args, timeout=600)

        self._worker = WorkerThread(run_bench)
        self._worker.finished.connect(self._on_benchmark_done)
        self._worker.start()

    def _on_benchmark_done(self, msg):
        self.log(msg)
        self.bm_btn.setEnabled(True)
        self.bm_btn.setText("Run Full Benchmark (may take several minutes)")
        self._worker = None


# =============================================================================
# Entry Point
# =============================================================================
def main():
    app = QApplication(sys.argv)

    dll_path = _find_dll()
    engine = None
    if dll_path:
        try:
            engine = SigEngine(dll_path)
            print(f"[INFO] Loaded DLL: {dll_path}")
        except Exception as e:
            print(f"[WARN] Failed to load DLL: {e}")

    if not engine:
        print("[INFO] No DLL found. GUI will use CLI subprocess mode.")

    window = Lab5Window(engine, dll_path)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
