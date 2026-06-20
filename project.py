import argparse
import base64
import json
from os import chmod, listdir, makedirs, urandom
from os.path import exists, splitext

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pwinput import pwinput
import pyperclip

# --- Setup paths ---
CREDENTIALS_DIR = "credentials"
PASSWORDS_DIR = "credentials/passwords"
KEYS_DIR = "credentials/keys"
SALT_PATH = "credentials/keys/salt.key"
LAST_VAULT_PATH = ".last_vault"


# --- Setup helpers ---
def ensure_credentials_dirs() -> bool:
    if exists(CREDENTIALS_DIR):
        return False
    makedirs(PASSWORDS_DIR, mode=0o700)
    makedirs(KEYS_DIR, mode=0o700)
    return True


def init_salt() -> bool:
    if exists(SALT_PATH):
        return False
    with open(SALT_PATH, "wb") as f:
        f.write(urandom(16))
    chmod(SALT_PATH, 0o600)
    return True


def read_salt() -> bytes:
    if not exists(SALT_PATH):
        raise FileNotFoundError("Salt file not found!")
    with open(SALT_PATH, "rb") as f:
        return f.read()


# --- Crypto helpers ---
def derive_key(salt: bytes, master_password: str) -> bytes:
    kdf = PBKDF2HMAC(
        # As of January 2025 Django recommends at least 1,200,000 iterations
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    # Fernet requires keys to be URL-safe Base64 encoded
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def encrypt_field(key: bytes, plaintext: str) -> str:
    return Fernet(key).encrypt(plaintext.encode()).decode()


def decrypt_field(key: bytes, ciphertext: str) -> str:
    return Fernet(key).decrypt(ciphertext.encode()).decode()


# --- Vault helpers ---
def vault_path(name: str) -> str:
    return f"{PASSWORDS_DIR}/{name}.json"


def list_vaults() -> list[str]:
    if not exists(PASSWORDS_DIR):
        return []
    return [splitext(file)[0] for file in listdir(PASSWORDS_DIR)]


def create_pass(pass_file: str) -> str:
    if pass_file == "":
        return "The password file can't be empty!"
    path = vault_path(pass_file)
    if exists(path):
        return f"There's already a file named {pass_file}.json!"
    with open(path, "w", encoding="utf-8") as f:
        json.dump([], f)
    chmod(path, 0o600)
    return f"Successfully created file named {pass_file}.json"


def load_entries(pass_file: str) -> list[dict]:
    path = vault_path(pass_file)
    if not exists(path):
        raise FileNotFoundError("The password file doesn't exist!")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_entries(pass_file: str, entries: list[dict]) -> None:
    path = vault_path(pass_file)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
    chmod(path, 0o600)


def add_entry(pass_file: str, key: bytes, site: str, password: str) -> None:
    if site == "" or password == "":
        raise ValueError("The site/password can't be empty!")
    entries = load_entries(pass_file)
    entries.append(
        {
            "site": encrypt_field(key, site),
            "password": encrypt_field(key, password),
        }
    )
    save_entries(pass_file, entries)


def decrypt_entry(key: bytes, entry: dict) -> tuple[str, str]:
    site = decrypt_field(key, entry["site"])
    password = decrypt_field(key, entry["password"])
    return site, password


def decrypt_entries(key: bytes, entries: list[dict]) -> list[tuple[str, str]]:
    return [decrypt_entry(key, entry) for entry in entries]


def get_default_vault() -> str | None:
    if not exists(LAST_VAULT_PATH):
        return None
    name = open(LAST_VAULT_PATH, encoding="utf-8").read().strip()
    if name and exists(vault_path(name)):
        return name
    return None


def set_default_vault(name: str) -> None:
    with open(LAST_VAULT_PATH, "w", encoding="utf-8") as f:
        f.write(name)


def search_entries(
    pass_file: str, key: bytes, query: str
) -> list[tuple[int, str, str]]:
    entries = load_entries(pass_file)
    query_lower = query.lower().strip()
    results = []
    for index, entry in enumerate(entries):
        try:
            site, password = decrypt_entry(key, entry)
        except InvalidToken:
            continue
        if query_lower == "" or query_lower in site.lower():
            results.append((index, site, password))
    return results


def verify_master_password(master_password: str, pass_file: str | None = None) -> bytes:
    key = derive_key(read_salt(), master_password)
    vaults = [pass_file] if pass_file else list_vaults()
    for vault_name in vaults:
        if vault_name is None:
            continue
        for entry in load_entries(vault_name):
            try:
                decrypt_entry(key, entry)
            except InvalidToken as exc:
                raise InvalidToken("Invalid master password!") from exc
    return key


# --- CLI helpers ---
def show_existing_files() -> None:
    print("""\n          Existing Password Files\n""")
    for name in list_vaults():
        print(name)


def main() -> None:
    if ensure_credentials_dirs():
        print("Credentials created.")
    if init_salt():
        print("Salt file created.")
    else:
        print("Existing salt file found.")
    show_menu()


def show_menu() -> None:
    while True:
        match input(
            """\n\n          Encrypted Password Manager\n
    [+] Create a new password file
    [1] Open Password Manager
    [Q] Quit\n\n"""
        ).lower().strip():
            case "+":
                show_existing_files()
                print(create_pass(input("\nCreate a password file named: ").strip()))
            case "1":
                # Hides user input with asterisks
                master_password = pwinput(prompt="Master password: ")
                show_existing_files()
                password_manager(
                    input("\nPassword file: ").strip(),
                    derive_key(read_salt(), master_password),
                )
            case "q":
                break


def get_password(pass_file: str, key: bytes) -> list[dict] | None:
    try:
        data = load_entries(pass_file)
    except FileNotFoundError:
        print("The password file doesn't exist!")
        return None
    if not data:
        print("Password file is empty!")
        return data
    print("""\n          Passwords\n""")
    for i, entry in enumerate(data):
        try:
            site, password = decrypt_entry(key, entry)
            print(f"    {i + 1}. {site}: {password}")
        except InvalidToken:
            print(f"    {i + 1}. Invalid master password!")
    return data


def password_manager(pass_file: str, key: bytes) -> None:
    if pass_file == "":
        print("The password file can't be empty!")
        return
    pass_path = vault_path(pass_file)
    if not exists(pass_path):
        print("The password file doesn't exist!")
        return
    while True:
        match input(
            "\n[A] Add a new password\n[E] Edit password\n[R] Remove password\n"
            "[G] Get passwords\n[Q] Cancel\n\n"
        ).lower().strip():
            case "a":
                new_site = input("\nSite: ").strip()
                new_password = input("Password: ").strip()
                try:
                    add_entry(pass_file, key, new_site, new_password)
                    print(f"Successfully added password to {pass_file}")
                except ValueError as exc:
                    print(exc)
            case "e":
                data = get_password(pass_file, key)
                if data is None:
                    continue
                try:
                    choice = int(input("\nType which number to edit: "))
                    site, password = decrypt_entry(key, data[choice - 1])
                    print(f"    {choice}. {site}: {password}")
                except InvalidToken:
                    print("    Invalid master password!")
                    continue
                except (ValueError, IndexError, TypeError):
                    print("     Invalid input!")
                    continue

                section = input("\nEdit:\n[1] Site\n[2] Password\n[Q] Cancel\n").lower().strip()

                if section == "1":
                    new_site = input("Change site to: ").strip()
                    if new_site == "":
                        print("The site can't be empty!")
                        continue
                    data[choice - 1]["site"] = encrypt_field(key, new_site)
                    save_entries(pass_file, data)
                    print(f"    {choice}. {new_site}: {password}")
                elif section == "2":
                    new_password = input("Change password to: ").strip()
                    if new_password == "":
                        print("The password can't be empty!")
                        continue
                    data[choice - 1]["password"] = encrypt_field(key, new_password)
                    save_entries(pass_file, data)
                    print(f"    {choice}. {site}: {new_password}")
                elif section == "q":
                    print("Canceled.")
                else:
                    print("Invalid input.")
            case "r":
                data = get_password(pass_file, key)
                if data is None:
                    continue
                try:
                    choice = int(input("\nType which number to remove: "))
                    site, password = decrypt_entry(key, data[choice - 1])
                    print(f"    {choice}. {site}: {password}")
                except InvalidToken:
                    print("    Invalid master password!")
                    continue
                except (ValueError, IndexError, TypeError):
                    print("     Invalid input!")
                    continue

                confirmation = input(
                    "Are you sure you want to delete this entry? This cannot be undone.\n[Y]/[N]\n"
                ).lower().strip()
                if confirmation == "y":
                    data.pop(choice - 1)
                    save_entries(pass_file, data)
                elif confirmation == "n":
                    print("Canceled.")
                else:
                    print("Invalid input! Canceled.")
            case "g":
                get_password_options(pass_file, key)
            case "q":
                break


def get_password_options(pass_file: str, key: bytes) -> None:
    data = get_password(pass_file, key)
    if data is None:
        return
    while True:
        match input(
            """\n[C] Copy password to clipboard\n[Q] Cancel\n\n"""
        ).lower().strip():
            case "c":
                try:
                    choice = int(input("\nType which number to copy: "))
                    _, password = decrypt_entry(key, data[choice - 1])
                    pyperclip.copy(password)
                    print("Password copied to clipboard.")
                    break
                except InvalidToken:
                    print("     Invalid master password!")
                    data = get_password(pass_file, key)
                    if data is None:
                        return
                    continue
                except (ValueError, IndexError, TypeError):
                    print("     Invalid input!")
                    data = get_password(pass_file, key)
                    if data is None:
                        return
                    continue
            case "q":
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fernet Password Manager")
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run the text menu interface for debugging",
    )
    args = parser.parse_args()
    if args.cli:
        main()
    else:
        from gui import run_gui

        run_gui()
