# Fernet Password Manager

A password manager that allows the user to add their passwords, encrypted using `cryptography`'s `Fernet` library, and view their passwords back any time.

## Demo

[YouTube](https://youtu.be/CGlx-yFMKVs)

The video is a bit outdated — it shows the original CLI version with separate key files, not the current GUI and master password setup.

## Description

`project.py` opens a GUI in which you can create a new password vault, unlock it with a master password, or open the original menu with `--cli`.

When creating a new password vault, you can name it to your liking. An error message prints if you type in nothing or the name of an existing file. `project.py` will create the vault and use your master password to encrypt and decrypt it.

When you open the password manager, input the vault name and master password. Like before, you will get an error message if you, for example, type in a vault that doesn't exist or the wrong master password. Afterwards, you can add a password, search your added passwords, or copy one to the clipboard.

When you add a password, `project.py` will encrypt it using your master password and store it in your vault.

On the other hand, when viewing your added passwords, `project.py` will read your vault and decrypt it. It's vital to use the same master password when encrypting and decrypting the password, or else it can't get decrypted.

`test_project.py` uses `pytest` to test `project.py`. For example, `project.py` should return an error message if the user inputs nothing, a file already exists with the user's inputted file name, a different master password was used to decrypt a vault, et cetera.

## Features

- Create multiple vaults to organise passwords
- Add new passwords
- Search added passwords
- Copy passwords to the clipboard

## Requirements

Install the requirements with `pip`:

```bash
pip install -r requirements.txt
```

## Design Choices

I initially used `print` to print out error messages, but after trying to test `project.py` using `pytest`, I decided it was easier to use `return` instead. By doing so, testing and finding bugs became significantly more straightforward.
