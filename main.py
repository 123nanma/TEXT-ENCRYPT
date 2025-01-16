import sys
import os  # This is the missing import
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QLabel, QMessageBox

# Function to generate a valid AES key from the password
def generate_key(password):
    return hashlib.sha256(password.encode('utf-8')).digest()


# Function to encrypt the text
def encrypt_text():
    try:
        # Get the text from the text input
        text = text_input.text()
        if not text:
            QMessageBox.critical(window, "Error", "Please enter some text to encrypt.")
            return

        # Get the password from the line edit widget
        password = password_input.text()
        if not password:
            QMessageBox.critical(window, "Error", "Please enter a password.")
            return

        # Generate a valid AES key and IV from the password
        key = generate_key(password)  # Generate 32-byte key using SHA-256
        iv = os.urandom(16)  # Generate a random 16-byte IV

        # Padding the text data to make it a multiple of 128 bits
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text.encode('utf-8')) + padder.finalize()

        # Encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Convert the encrypted data to a base64 encoded string for easier display
        encrypted_text = base64.b64encode(iv + encrypted_data).decode('utf-8')

        encrypted_text_output.setText(encrypted_text)
        QMessageBox.information(window, "Success", "Text encrypted successfully!")

    except Exception as e:
        QMessageBox.critical(window, "Error", f"An error occurred during encryption: {str(e)}")


# Function to decrypt the text
def decrypt_text():
    try:
        # Get the encrypted text from the text input
        encrypted_text = encrypted_text_output.text()
        if not encrypted_text:
            QMessageBox.critical(window, "Error", "Please enter encrypted text to decrypt.")
            return

        # Get the password from the line edit widget
        password = password_input.text()
        if not password:
            QMessageBox.critical(window, "Error", "Please enter a password.")
            return

        # Decode the encrypted text from base64
        encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))

        # Extract the IV and encrypted data
        iv = encrypted_data[:16]  # First 16 bytes are the IV
        encrypted_data = encrypted_data[16:]

        # Generate the key from the password
        key = generate_key(password)  # Generate 32-byte key using SHA-256

        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_text = unpadder.update(decrypted_data) + unpadder.finalize()

        # Show the decrypted text
        decrypted_text_output.setText(decrypted_text.decode('utf-8'))
        QMessageBox.information(window, "Success", "Text decrypted successfully!")

    except Exception as e:
        QMessageBox.critical(window, "Error", f"An error occurred during decryption: {str(e)}")


# Setting up the PyQt5 application
app = QApplication(sys.argv)

# Main window setup
window = QWidget()
window.setWindowTitle("Text Encrypter/Decrypter")
window.setGeometry(100, 100, 400, 300)

# Layout setup
layout = QVBoxLayout()

# Title label
title_label = QLabel("Text Encrypter & Decrypter")
layout.addWidget(title_label)

# Password input
password_label = QLabel("Enter Password:")
layout.addWidget(password_label)

password_input = QLineEdit()
password_input.setEchoMode(QLineEdit.Password)
layout.addWidget(password_input)

# Text input for plain text
text_label = QLabel("Enter Text to Encrypt:")
layout.addWidget(text_label)

text_input = QLineEdit()
layout.addWidget(text_input)

# Encrypt button
encrypt_button = QPushButton("Encrypt Text")
encrypt_button.clicked.connect(encrypt_text)
layout.addWidget(encrypt_button)

# Output for encrypted text
encrypted_text_label = QLabel("Encrypted Text (Base64):")
layout.addWidget(encrypted_text_label)

encrypted_text_output = QLineEdit()
encrypted_text_output.setReadOnly(True)
layout.addWidget(encrypted_text_output)

# Decrypt button
decrypt_button = QPushButton("Decrypt Text")
decrypt_button.clicked.connect(decrypt_text)
layout.addWidget(decrypt_button)

# Output for decrypted text
decrypted_text_label = QLabel("Decrypted Text:")
layout.addWidget(decrypted_text_label)

decrypted_text_output = QLineEdit()
decrypted_text_output.setReadOnly(True)
layout.addWidget(decrypted_text_output)

# Set layout and show window
window.setLayout(layout)
window.show()

# Run the application
sys.exit(app.exec_())
