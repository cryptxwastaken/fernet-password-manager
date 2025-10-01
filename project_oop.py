import base64
from os import makedirs, urandom, listdir, chmod
from os.path import exists, splitext
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pwinput import pwinput
import pyperclip


class PasswordManager:
    def __init__(self):
        self.keys_dir = "credentials/keys"
        self.passwords_dir = "credentials/passwords"
        self.salt_path = f"{self.keys_dir}/salt.key"
    
    def ensure_environment(self):
        if not exists("credentials"):
        # Only the owner can read, write, or enter the directory
            makedirs(self.passwords_dir, mode=0o700)
            makedirs(self.keys_dir, mode=0o700)
            print("Credentials created.")

        if not exists(self.salt_path):
            with open(self.salt_path, "wb") as f:
                # Secure values are 16 bytes or longer
                f.write(urandom(16))
            # Set file permissions to read/write only for the owner
            chmod(self.salt_path, 0o600)
            print("Salt file created.")
        else:
            print("Existing salt file found.")



    def run(self):
        self.ensure_environment()

if __name__ == "__main__":
    PasswordManager().run()
