from __future__ import annotations

import sys
from dataclasses import dataclass

import pyperclip
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QFileDialog,
    QSpinBox,
    QVBoxLayout,
    QWidget,
    QInputDialog,
)

from .crypto import CipherEngine, DecryptionOptions, EncryptionOptions
from .network_client import NetworkKeyClient, NetworkPolicy
from .system_identity import get_or_create_system_id


@dataclass
class AppConfig:
    server_url: str = "https://192.168.10.20:8443"
    tenant: str = "company-default"


class MainWindow(QMainWindow):
    def __init__(self, engine: CipherEngine):
        super().__init__()
        self.engine = engine
        self.setWindowTitle("Cipherlocks Professional")
        self.setMinimumSize(800, 360)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)

        file_group = QGroupBox("File")
        file_layout = QGridLayout(file_group)
        self.file_path = QLineEdit()
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self._browse)
        file_layout.addWidget(QLabel("Path"), 0, 0)
        file_layout.addWidget(self.file_path, 0, 1)
        file_layout.addWidget(browse_button, 0, 2)

        security_group = QGroupBox("Security Policy")
        security_form = QFormLayout(security_group)
        self.random_name = QCheckBox("Random output filename")
        self.secure_delete = QCheckBox("Secure-delete original file")
        self.require_lan = QCheckBox("Require LAN key-share server")
        self.attempt_limit_enabled = QCheckBox("Enable max decryption attempts")
        self.attempt_limit = QSpinBox()
        self.attempt_limit.setRange(1, 20)
        self.attempt_limit.setValue(3)
        security_form.addRow(self.random_name)
        security_form.addRow(self.secure_delete)
        security_form.addRow(self.require_lan)
        security_form.addRow(self.attempt_limit_enabled, self.attempt_limit)

        controls = QHBoxLayout()
        encrypt_button = QPushButton("Encrypt")
        encrypt_button.clicked.connect(self._encrypt)
        decrypt_button = QPushButton("Decrypt")
        decrypt_button.clicked.connect(self._decrypt)
        controls.addWidget(encrypt_button)
        controls.addWidget(decrypt_button)

        system_id = get_or_create_system_id()
        self.sys_id_label = QLabel(f"System ID: {system_id}")
        self.sys_id_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        copy_button = QPushButton("Copy System ID")
        copy_button.clicked.connect(lambda: self._copy(system_id))

        layout.addWidget(file_group)
        layout.addWidget(security_group)
        layout.addLayout(controls)
        layout.addWidget(self.sys_id_label)
        layout.addWidget(copy_button)

        self.setCentralWidget(root)

    def _copy(self, text: str) -> None:
        pyperclip.copy(text)
        QMessageBox.information(self, "Copied", "System ID copied to clipboard.")

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path:
            self.file_path.setText(path)

    def _prompt_password(self, title: str) -> str | None:
        value, ok = QInputDialog.getText(self, title, "Password", QLineEdit.Password)
        return value if ok and value else None

    def _encrypt(self) -> None:
        path = self.file_path.text().strip()
        if not path:
            QMessageBox.warning(self, "Missing file", "Please choose a file first.")
            return

        password = self._prompt_password("Encryption Password")
        if not password:
            return

        options = EncryptionOptions(
            max_attempts=self.attempt_limit.value() if self.attempt_limit_enabled.isChecked() else -1,
            random_filename=self.random_name.isChecked(),
            delete_original=self.secure_delete.isChecked(),
            require_lan_key=self.require_lan.isChecked(),
            user_id="desktop-user",
        )

        try:
            output = self.engine.encrypt_file(path, password, options)
            QMessageBox.information(self, "Success", f"Encrypted file created:\n{output}")
        except Exception as exc:
            QMessageBox.critical(self, "Encryption failed", str(exc))

    def _decrypt(self) -> None:
        path = self.file_path.text().strip()
        if not path.endswith(".enc"):
            QMessageBox.warning(self, "Invalid file", "Please select a .enc file.")
            return

        password = self._prompt_password("Decryption Password")
        if not password:
            return

        try:
            output = self.engine.decrypt_file(path, password, DecryptionOptions(user_id="desktop-user"))
            QMessageBox.information(self, "Success", f"Decrypted file restored:\n{output}")
        except Exception as exc:
            QMessageBox.critical(self, "Decryption failed", str(exc))



def build_engine(config: AppConfig) -> CipherEngine:
    policy = NetworkPolicy(server_url=config.server_url, tenant=config.tenant)
    return CipherEngine(NetworkKeyClient(policy))



def run_app() -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow(build_engine(AppConfig()))
    window.show()
    return app.exec()
