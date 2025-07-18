import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import makedirs
from os.path import exists
from os import urandom


def main():
    if not exists("credentials"):
        makedirs("credentials/passwords")
        makedirs("credentials/keys")
        print("Credentials created.")

    salt_path = "credentials/keys/salt.key"
    if not exists(salt_path):
        with open(salt_path, "wb") as f:
            # Secure values are 16 bytes or longer
            f.write(urandom(16))
        print("Salt file created.")
    else:
        print("Exisiting salt file found.")

    show_menu()


def read_salt():
    salt_path = "credentials/keys/salt.key"
    if exists(salt_path):
        with open(salt_path, "rb") as f:
            salt = f.read()
    return salt

def derive_key(salt, master_password):
    kdf = PBKDF2HMAC(
    algorithm = hashes.SHA256(),
    length = 32,
    salt = salt,
    # As of January 2025 Django recommends at least 1,200,000 iterations
    iterations = 1_200_000,
    )
    # Fernet requires keys to be URL-safe Base64 encoded 
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def show_menu():
    while True:
        match input(
            """\n\n          Encrypted Password Manager\n
    [+] Create a new password file
    [1] Open Password Manager
    [Q] Quit\n\n"""
        ).lower().strip():
            case "+":
                print(create_pass(input("\nCreate a password file named: ").strip()))
            case "1":
                master_password = input("Master password: ")
                password_manager(
                    input("\nPassword file: ").strip(), derive_key(read_salt(), master_password)
                )
            case "q":
                break


def create_pass(pass_file):
    if pass_file == "":
        return "The password file can't be empty!"
    pass_path = f"credentials/passwords/{pass_file}.pass"
    try:
        with open(pass_path) as _:
            return f"There's already a file named {pass_file}.pass!"
    except FileNotFoundError:
        with open(pass_path, "w") as _:
            return f"Successfully created file named {pass_file}.pass"


def password_manager(pass_file, key):
    if pass_file == "":
        print("The password file can't be empty!")
        return
    pass_path = f"credentials/passwords/{pass_file}.pass"
    if not exists(pass_path):
        print("The password file doesn't exist!")
        return
    while True:
        match input(
            """\n[A] Add a new password\n[G] Get passwords\n[Q] Cancel\n\n"""
        ).lower().strip():
            case "a":
                new_site = input("\nSite: ").strip()
                new_password = input("Password: ").strip()
                if new_site == "" or new_password == "":
                    print("The site/password can't be empty!")
                    continue
                encrypt_pass = Fernet(key).encrypt(new_password.encode())
                with open(pass_path, "a") as f:
                    f.write(f"{new_site}:{encrypt_pass.decode()}\n")
                print(f"Successfully added password to {pass_file}.pass")
            case "g":
                with open(pass_path, "rb") as f:
                    list = f.readlines()
                print("""\n          Passwords\n""")
                for i, line in enumerate(list):
                    site, encrypted_pass = line.decode().split(":")
                    try:
                        password = Fernet(key).decrypt(encrypted_pass.encode()).decode()
                        print(f"    {i + 1}. {site}: {password}")
                    except InvalidToken:
                        print(f"    {i + 1}. Invalid key!")
            case "q":
                break


if __name__ == "__main__":
    main()
