from cryptography.fernet import Fernet, InvalidToken


def main():
    show_menu()


def show_menu():
    while True:
        match input(
            """\n\n          Encrypted Password Manager\n
    (_) Create a new key
    (+) Create a new password file
    (1) Open Password Manager
    (Q) Quit\n\n"""
        ).lower().strip():
            case "_":
                print(create_key(input("\nCreate a key named: ").strip()))
            case "+":
                print(create_pass(input("\nCreate a password file named: ").strip()))
            case "1":
                manage_pass(
                    input("\nPassword file: ").strip(), load_key(input("Key: ").strip())
                )
            case "q":
                break


def create_key(key_file):
    if key_file == "":
        return "The key can't be empty!"
    try:
        with open(f"{key_file}.key") as _:
            return f"There's already a file named {key_file}.key!"
    except FileNotFoundError:
        with open(f"{key_file}.key", "wb") as f:
            f.write(Fernet.generate_key())
        return f"Successfully created file named {key_file}.key"


def create_pass(pass_file):
    if pass_file == "":
        return "The password file can't be empty!"
    try:
        with open(f"{pass_file}.pass") as _:
            return f"There's already a file named {pass_file}.pass!"
    except FileNotFoundError:
        with open(f"{pass_file}.pass", "w") as _:
            return f"Successfully created file named {pass_file}.pass"


def load_key(key_file):
    if key_file == "":
        return ""
    try:
        with open(f"{key_file}.key", "rb") as f:
            return f.read()
    except FileNotFoundError:
        return


def manage_pass(pass_file, key):
    if pass_file == "" or key == "":
        print("The password file/key can't be empty!")
        return
    try:
        if open(f"{pass_file}.pass"):
            if key == None:
                print("The key doesn't exist!")
                return
    except FileNotFoundError:
        if key == None:
            print("The password file/key doesn't exist!")
            return
        print("The password file doesn't exist!")
        return
    while True:
        match input(
            """\n(A) Add a new password\n(G) Get passwords\n(Q) Cancel\n\n"""
        ).lower().strip():
            case "a":
                new_site = input("\nSite: ").strip()
                new_password = input("Password: ").strip()
                if new_site == "" or new_password == "":
                    print("The site/password can't be empty!")
                    continue
                encrypt_pass = Fernet(key).encrypt(new_password.encode())
                with open(f"{pass_file}.pass", "a") as f:
                    f.write(f"{new_site}:{encrypt_pass.decode()}\n")
                print(f"Successfully added password to {pass_file}.pass")
            case "g":
                with open(f"{pass_file}.pass", "rb") as f:
                    list = f.readlines()
                print("""\n          Passwords\n""")
                for i, line in enumerate(list):
                    site, encrypted_pass = line.decode().split(":")
                    try:
                        password = Fernet(key).decrypt(encrypted_pass).decode()
                        print(f"    {i + 1}. {site}: {password}")
                    except InvalidToken:
                        print(f"    {i + 1}. Invalid key!")
            case "q":
                break


if __name__ == "__main__":
    main()
