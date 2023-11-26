# Fernet Password Manager

A password manager that allows the user to add their passwords, encrypted using `cryptography`'s `Fernet` library, and view their passwords back any time.

## Demo

[YouTube](https://youtu.be/CGlx-yFMKVs)

## Description

`project.py` shows a menu in which you can create a new key, create a new password file, or open the password manager.

When creating a new password file and key, you can name them to your liking. An error message prints if you type in nothing or the name of an existing file. `project.py` will generate a key using `Fernet` and store it in the key file.

When you open the password manager, input the names of the password file and key you created. Like before, you will get an error message if you, for example, type in a password file/key that doesn't exist. Afterwards, you can add a password or view all your added passwords.

When you add a password, `project.py` will encrypt it using your key and store it in your password file.

On the other hand, when viewing your added passwords, `project.py` will read your password file and decrypt it. It's vital to use the same key when encrypting and decrypting the password, or else it can't get decrypted.

`test_project.py` uses `pytest` to test `project.py`. For example, `project.py` should return an error message if the user inputs nothing, a file already exists with the user's inputted file name, a different key was used to decrypt a password file, et cetera.

## Features

- Create unique keys for encryption
- Create multiple files to organise passwords
- Add new passwords
- View all added passwords

## Requirements

Install `cryptography` with `pip`:

```bash
pip install cryptography
```

## Design Choices

I initially used `print` to print out error messages, but after trying to test `project.py` using `pytest`, I decided it was easier to use `return` instead. By doing so, testing and finding bugs became significantly more straightforward.
