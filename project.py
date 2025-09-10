import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import makedirs, urandom, listdir, chmod
from os.path import exists, splitext
import json
from pwinput import pwinput
import pyperclip


def show_existing_files():
    print("""\n          Existing Password Files\n""")
    dir_list = listdir("credentials/passwords")
    for file in dir_list:
        print(splitext(file)[0])


def main():
    if not exists("credentials"):
        # Only the owner can read, write, or enter the directory
        makedirs("credentials/passwords", mode=0o700)
        makedirs("credentials/keys", mode=0o700)
        print("Credentials created.")

    salt_path = "credentials/keys/salt.key"
    if not exists(salt_path):
        with open(salt_path, "wb") as f:
            # Secure values are 16 bytes or longer
            f.write(urandom(16))
        # Set file permissions to read/write only for the owner
        chmod(salt_path, 0o600)
        print("Salt file created.")
    else:
        print("Existing salt file found.")

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
                show_existing_files()
                print(create_pass(input("\nCreate a password file named: ").strip()))
            case "1":
                # Hides user input with asterisks
                master_password = pwinput(prompt="Master password: ")
                show_existing_files()
                password_manager(
                    input("\nPassword file: ").strip(), derive_key(read_salt(), master_password)
                )
            case "q":
                break


def create_pass(pass_file):
    if pass_file == "":
        return "The password file can't be empty!"
    pass_path = f"credentials/passwords/{pass_file}.json"
    try:
        with open(pass_path) as _:
            return f"There's already a file named {pass_file}.json!"
    except FileNotFoundError:
        with open(pass_path, "w") as f:
            json.dump([], f)

        # Set file permissions to read/write only for the owner
        chmod(pass_path, 0o600)

        return f"Successfully created file named {pass_file}.json"
        

def get_password(pass_path, key):
    try:
        with open(pass_path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print("Password file is empty!")
        return
    print("""\n          Passwords\n""")
    for i, entry in enumerate(data):
        try:
            site = Fernet(key).decrypt(entry["site"].encode()).decode()
            password = Fernet(key).decrypt(entry["password"].encode()).decode()
            print(f"    {i + 1}. {site}: {password}")
        except InvalidToken:
            print(f"    {i + 1}. Invalid master password!")
    return data


def password_manager(pass_file, key):
    if pass_file == "":
        print("The password file can't be empty!")
        return
    pass_path = f"credentials/passwords/{pass_file}.json"
    if not exists(pass_path):
        print("The password file doesn't exist!")
        return
    while True:
        match input(
            """\n[A] Add a new password\n[E] Edit password\n[R] Remove password\n[G] Get passwords\n[Q] Cancel\n\n"""
        ).lower().strip():
            case "a":
                new_site = input("\nSite: ").strip()
                new_password = input("Password: ").strip()
                if new_site == "" or new_password == "":
                    print("The site/password can't be empty!")
                    continue
                try:
                    with open(pass_path, "r") as f:
                        data = json.load(f)
                except json.JSONDecodeError:
                    data = []
                encrypt_site = Fernet(key).encrypt(new_site.encode())
                encrypt_pass = Fernet(key).encrypt(new_password.encode())
                with open(pass_path, "w") as f:
                    encrypted = {
                        "site": encrypt_site.decode(),
                        "password": encrypt_pass.decode()
                    }
                    data.append(encrypted)
                    json.dump(data, f, indent=2)
                print(f"Successfully added password to {pass_file}")
            case "e":
                data = get_password(pass_path, key)
                try:
                    choice = int(input("\nType which number to edit: "))
                    site = Fernet(key).decrypt(data[choice - 1]["site"].encode()).decode()
                    password = Fernet(key).decrypt(data[choice - 1]["password"].encode()).decode()
                    print(f"    {choice}. {site}: {password}")
                except InvalidToken:
                    print(f"    Invalid master password!")
                    continue
                except:
                    print("     Invalid input!")
                    continue

                section = input("\nEdit:\n[1] Site\n[2] Password\n[Q] Cancel\n").lower().strip()

                if section == "1":
                    new_site = input("Change site to: ")
                    if new_site == "":
                        print("The site can't be empty!")
                        continue
                    encrypt_site = Fernet(key).encrypt(new_site.encode())

                    with open(pass_path, "w") as f:
                        data[choice - 1]["site"] = encrypt_site.decode()
                        json.dump(data, f, indent=2)

                    print(f"    {choice}. {new_site}: {password}")
                elif section == "2":
                    new_password = input("Change password to: ")
                    if new_password == "":
                        print("The password can't be empty!")
                        continue
                    encrypt_password = Fernet(key).encrypt(new_password.encode())

                    with open(pass_path, "w") as f:
                        data[choice - 1]["password"] = encrypt_password.decode()
                        json.dump(data, f, indent=2)

                    print(f"    {choice}. {site}: {new_password}")
                elif section == "q":
                    print("Canceled.")
                else:
                    print("Invalid input.")
            case "r":
                data = get_password(pass_path, key)
                try:
                    choice = int(input("\nType which number to remove: "))
                    site = Fernet(key).decrypt(data[choice - 1]["site"].encode()).decode()
                    password = Fernet(key).decrypt(data[choice - 1]["password"].encode()).decode()
                    print(f"    {choice}. {site}: {password}")
                except InvalidToken:
                    print(f"    {choice}. Invalid master password!")
                    continue
                except:
                    print("     Invalid input!")
                    continue
                
                confirmation = input("Are you sure you want to delete this entry? This cannot be undone.\n[Y]/[N]\n"
                                     ).lower().strip()
                if confirmation == "y":
                    with open(pass_path, "w") as f:
                        data.pop(choice - 1)
                        json.dump(data, f, indent=2)
                elif confirmation == "n":
                    print("Canceled.")
                else:
                    print("Invalid input! Canceled.")
            case "g":
                get_password_options(pass_path, key)
            case "q":
                break

def get_password_options(pass_path, key):
    data = get_password(pass_path, key)
    while True:
        match input(
            """\n[C] Copy password to clipboard\n[Q] Cancel\n\n"""
        ).lower().strip():
            case "c":
                try:
                    choice = int(input("\nType which number to copy: "))
                    password = Fernet(key).decrypt(data[choice - 1]["password"].encode()).decode()
                    pyperclip.copy(password)
                    print("Password copied to clipboard.")
                    break
                except InvalidToken:
                    print(f"     Invalid master password!")
                    get_password(pass_path, key)
                    continue
                except:
                    print("     Invalid input!")
                    get_password(pass_path, key)
                    continue
            case "q":
                break


if __name__ == "__main__":
    main()
