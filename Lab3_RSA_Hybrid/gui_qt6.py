#!/usr/bin/env python3
"""Lab 3 RSA-OAEP & Hybrid Encryption GUI - Calls compiled DLL via ctypes (bonus +5 points)"""

import sys
import os
import ctypes
from pathlib import Path
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *


class RSAEngine:
    """Wrapper around rsatool.dll using ctypes - ALL features in one DLL"""
    
    def __init__(self, dll_path):
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"DLL not found: {dll_path}")
        
        self.dll = ctypes.CDLL(dll_path)
        
        # Key Generation
        self.dll.lab3_keygen.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        self.dll.lab3_keygen.restype = ctypes.c_int
        
        # Encryption/Decryption
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
        
        # Benchmark
        self.dll.lab3_run_benchmark.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p
        ]
        self.dll.lab3_run_benchmark.restype = ctypes.c_char_p
        
        # Tests
        self.dll.lab3_run_tests.argtypes = [
            ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int), ctypes.c_char_p
        ]
        self.dll.lab3_run_tests.restype = ctypes.c_char_p
        
        # KAT
        self.dll.lab3_run_kat.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p
        ]
        self.dll.lab3_run_kat.restype = ctypes.c_char_p
    
    def keygen(self, bits, pub_file, priv_file):
        """Generate RSA key pair"""
        error_buf = ctypes.create_string_buffer(1024)
        
        result = self.dll.lab3_keygen(
            bits,
            pub_file.encode('utf-8'),
            priv_file.encode('utf-8'),
            error_buf
        )
        
        if result != 0:
            raise RuntimeError(error_buf.value.decode('utf-8'))
    
    def encrypt(self, pub_key_file, plaintext, label, output_file, aad_hex=""):
        """Encrypt using DLL"""
        error_buf = ctypes.create_string_buffer(1024)
        
        result = self.dll.lab3_encrypt(
            pub_key_file.encode('utf-8'),
            plaintext.encode('utf-8'),
            label.encode('utf-8') if label else b"",
            aad_hex.encode('utf-8') if aad_hex else b"",
            output_file.encode('utf-8'),
            error_buf
        )
        
        if result is None:
            raise RuntimeError(error_buf.value.decode('utf-8'))
        
        return result.decode('utf-8')
    
    def decrypt(self, priv_key_file, input_file, label, output_file):
        """Decrypt using DLL"""
        error_buf = ctypes.create_string_buffer(1024)
        
        result = self.dll.lab3_decrypt(
            priv_key_file.encode('utf-8'),
            input_file.encode('utf-8'),
            label.encode('utf-8') if label else b"",
            output_file.encode('utf-8'),
            error_buf
        )
        
        if result != 0:
            raise RuntimeError(error_buf.value.decode('utf-8'))
    
    def run_benchmark(self, mode="all"):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab3_run_benchmark(
            mode.encode('utf-8'),
            error_buf
        )
        if result is None:
            raise RuntimeError(error_buf.value.decode('utf-8'))
        return result.decode('utf-8')
    
    def run_tests(self):
        error_buf = ctypes.create_string_buffer(1024)
        total = ctypes.c_int(0)
        passed = ctypes.c_int(0)
        failed = ctypes.c_int(0)
        
        result = self.dll.lab3_run_tests(
            ctypes.byref(total),
            ctypes.byref(passed),
            ctypes.byref(failed),
            error_buf
        )
        
        if result is None:
            raise RuntimeError(error_buf.value.decode('utf-8'))
        
        return result.decode('utf-8'), total.value, passed.value, failed.value
    
    def run_kat(self, vectors_file):
        error_buf = ctypes.create_string_buffer(1024)
        result = self.dll.lab3_run_kat(
            vectors_file.encode('utf-8'),
            error_buf
        )
        if result is None:
            raise RuntimeError(error_buf.value.decode('utf-8'))
        return result.decode('utf-8')


class Lab3GUI(QWidget):
    def __init__(self):
        super().__init__()
        self.engine = None
        self.pub_key_file = ""
        self.priv_key_file = ""
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Lab 3 - RSA-OAEP & Hybrid Encryption (DLL Mode)")
        self.resize(800, 750)
        
        layout = QVBoxLayout(self)
        
        # DLL path selector
        dll_group = QGroupBox("1. Select DLL Library")
        dll_layout = QHBoxLayout()
        self.dll_path = QLineEdit()
        self.dll_path.setPlaceholderText("Select rsatool.dll...")
        dll_btn = QPushButton("Browse...")
        dll_btn.clicked.connect(self.browse_dll)
        dll_layout.addWidget(self.dll_path)
        dll_layout.addWidget(dll_btn)
        dll_group.setLayout(dll_layout)
        layout.addWidget(dll_group)
        
        # Load DLL button
        load_btn = QPushButton("Load DLL")
        load_btn.clicked.connect(self.load_dll)
        layout.addWidget(load_btn)
        
        # Tabs
        tabs = QTabWidget()
        
        # Key Generation Tab
        keygen_tab = self.create_keygen_tab()
        tabs.addTab(keygen_tab, "Key Generation")
        
        # Encryption Tab
        encrypt_tab = self.create_encrypt_tab()
        tabs.addTab(encrypt_tab, "Encryption")
        
        # Decryption Tab
        decrypt_tab = self.create_decrypt_tab()
        tabs.addTab(decrypt_tab, "Decryption")
        
        layout.addWidget(tabs)
        
        # Status
        self.status_bar = QLabel("Status: DLL not loaded")
        self.status_bar.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(self.status_bar)
    
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
        pub_browse.clicked.connect(lambda: self.browse_save_file("Save Public Key", "pub_key.pem"))
        pub_layout.addWidget(self.pub_key_edit)
        pub_layout.addWidget(pub_browse)
        layout.addRow("Public Key:", pub_layout)
        
        priv_layout = QHBoxLayout()
        self.priv_key_edit = QLineEdit()
        self.priv_key_edit.setPlaceholderText("private_key.pem")
        priv_browse = QPushButton("Browse...")
        priv_browse.clicked.connect(lambda: self.browse_save_file("Save Private Key", "priv_key.pem"))
        priv_layout.addWidget(self.priv_key_edit)
        priv_layout.addWidget(priv_browse)
        layout.addRow("Private Key:", priv_layout)
        
        self.keygen_btn = QPushButton("Generate Key Pair")
        self.keygen_btn.clicked.connect(self.do_keygen)
        self.keygen_btn.setEnabled(False)
        layout.addRow(self.keygen_btn)
        
        return tab
    
    def create_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        pub_layout = QHBoxLayout()
        self.enc_pub_edit = QLineEdit()
        self.enc_pub_edit.setPlaceholderText("Load public key...")
        pub_browse = QPushButton("Browse...")
        pub_browse.clicked.connect(self.browse_pub_key)
        pub_layout.addWidget(self.enc_pub_edit)
        pub_layout.addWidget(pub_browse)
        layout.addWidget(QLabel("Public Key:"))
        layout.addLayout(pub_layout)
        
        self.label_edit = QLineEdit()
        self.label_edit.setPlaceholderText("Optional OAEP label")
        layout.addWidget(QLabel("OAEP Label (optional):"))
        layout.addWidget(self.label_edit)
        
        self.plaintext_edit = QTextEdit()
        self.plaintext_edit.setPlaceholderText("Enter plaintext to encrypt...")
        self.plaintext_edit.setMaximumHeight(100)
        layout.addWidget(QLabel("Plaintext:"))
        layout.addWidget(self.plaintext_edit)
        
        out_layout = QHBoxLayout()
        self.out_file_edit = QLineEdit()
        self.out_file_edit.setPlaceholderText("output.bin")
        out_browse = QPushButton("Browse...")
        out_browse.clicked.connect(lambda: self.browse_save_file("Save Output", "output.bin"))
        out_layout.addWidget(self.out_file_edit)
        out_layout.addWidget(out_browse)
        layout.addWidget(QLabel("Output File:"))
        layout.addLayout(out_layout)
        
        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.do_encrypt)
        self.encrypt_btn.setEnabled(False)
        layout.addWidget(self.encrypt_btn)
        
        self.enc_result = QTextEdit()
        self.enc_result.setReadOnly(True)
        self.enc_result.setMaximumHeight(100)
        layout.addWidget(QLabel("Result:"))
        layout.addWidget(self.enc_result)
        
        return tab
    
    def create_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        priv_layout = QHBoxLayout()
        self.dec_priv_edit = QLineEdit()
        self.dec_priv_edit.setPlaceholderText("Load private key...")
        priv_browse = QPushButton("Browse...")
        priv_browse.clicked.connect(self.browse_priv_key)
        priv_layout.addWidget(self.dec_priv_edit)
        priv_layout.addWidget(priv_browse)
        layout.addWidget(QLabel("Private Key:"))
        layout.addLayout(priv_layout)
        
        in_layout = QHBoxLayout()
        self.in_file_edit = QLineEdit()
        self.in_file_edit.setPlaceholderText("Select input file...")
        in_browse = QPushButton("Browse...")
        in_browse.clicked.connect(self.browse_input_file)
        in_layout.addWidget(self.in_file_edit)
        in_layout.addWidget(in_browse)
        layout.addWidget(QLabel("Input File:"))
        layout.addLayout(in_layout)
        
        self.dec_label_edit = QLineEdit()
        self.dec_label_edit.setPlaceholderText("Optional OAEP label")
        layout.addWidget(QLabel("OAEP Label (optional):"))
        layout.addWidget(self.dec_label_edit)
        
        out_layout = QHBoxLayout()
        self.dec_out_edit = QLineEdit()
        self.dec_out_edit.setPlaceholderText("output.txt")
        out_browse = QPushButton("Browse...")
        out_browse.clicked.connect(lambda: self.browse_save_file("Save Decrypted", "output.txt"))
        out_layout.addWidget(self.dec_out_edit)
        out_layout.addWidget(out_browse)
        layout.addWidget(QLabel("Output File:"))
        layout.addLayout(out_layout)
        
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.do_decrypt)
        self.decrypt_btn.setEnabled(False)
        layout.addWidget(self.decrypt_btn)
        
        self.dec_result = QTextEdit()
        self.dec_result.setReadOnly(True)
        self.dec_result.setMaximumHeight(100)
        layout.addWidget(QLabel("Decrypted Text:"))
        layout.addWidget(self.dec_result)
        
        return tab
    
    def browse_dll(self):
        dll_path, _ = QFileDialog.getOpenFileName(
            self, "Select DLL", "", "DLL Files (*.dll);;All Files (*)"
        )
        if dll_path:
            self.dll_path.setText(dll_path)
    
    def browse_save_file(self, title, default):
        file_path, _ = QFileDialog.getSaveFileName(self, title, default, "All Files (*)")
        return file_path
    
    def browse_pub_key(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Public Key", "", "PEM Files (*.pem);;All Files (*)"
        )
        if file_path:
            self.enc_pub_edit.setText(file_path)
    
    def browse_priv_key(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Private Key", "", "PEM Files (*.pem);;All Files (*)"
        )
        if file_path:
            self.dec_priv_edit.setText(file_path)
    
    def browse_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Input File", "", "All Files (*)"
        )
        if file_path:
            self.in_file_edit.setText(file_path)
    
    def load_dll(self):
        try:
            path = self.dll_path.text()
            if not path:
                QMessageBox.warning(self, "Error", "Please select a DLL file")
                return
            
            self.engine = RSAEngine(path)
            self.status_bar.setText(f"Status: DLL loaded successfully")
            self.status_bar.setStyleSheet("color: green; font-weight: bold;")
            self.keygen_btn.setEnabled(True)
            self.encrypt_btn.setEnabled(True)
            self.decrypt_btn.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load DLL: {e}")
            self.status_bar.setText(f"Status: Failed to load DLL")
    
    def do_keygen(self):
        try:
            bits = int(self.bits_combo.currentText())
            pub_file = self.pub_key_edit.text()
            priv_file = self.priv_key_edit.text()
            
            if not pub_file or not priv_file:
                QMessageBox.warning(self, "Error", "Please specify both key file paths")
                return
            
            self.engine.keygen(bits, pub_file, priv_file)
            self.status_bar.setText(f"Status: Generated RSA-{bits} key pair")
            self.status_bar.setStyleSheet("color: blue; font-weight: bold;")
            QMessageBox.information(self, "Success", f"RSA-{bits} key pair generated successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation failed: {e}")
    
    def do_encrypt(self):
        try:
            pub_file = self.enc_pub_edit.text()
            if not pub_file:
                QMessageBox.warning(self, "Error", "Please load a public key")
                return
            
            out_file = self.out_file_edit.text()
            if not out_file:
                QMessageBox.warning(self, "Error", "Please specify an output file")
                return
            
            result = self.engine.encrypt(
                pub_file,
                self.plaintext_edit.toPlainText(),
                self.label_edit.text(),
                out_file
            )
            
            self.enc_result.setText(result)
            self.status_bar.setText("Status: Encryption successful")
            self.status_bar.setStyleSheet("color: blue; font-weight: bold;")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {e}")
    
    def do_decrypt(self):
        try:
            priv_file = self.dec_priv_edit.text()
            if not priv_file:
                QMessageBox.warning(self, "Error", "Please load a private key")
                return
            
            in_file = self.in_file_edit.text()
            if not in_file:
                QMessageBox.warning(self, "Error", "Please select an input file")
                return
            
            out_file = self.dec_out_edit.text()
            if not out_file:
                QMessageBox.warning(self, "Error", "Please specify an output file")
                return
            
            self.engine.decrypt(
                priv_file,
                in_file,
                self.dec_label_edit.text(),
                out_file
            )
            
            # Read decrypted file
            with open(out_file, 'r', errors='ignore') as f:
                decrypted = f.read()
            
            self.dec_result.setText(decrypted)
            self.status_bar.setText("Status: Decryption successful")
            self.status_bar.setStyleSheet("color: blue; font-weight: bold;")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = Lab3GUI()
    gui.show()
    sys.exit(app.exec())
