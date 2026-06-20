import pytest
from cryptography.fernet import InvalidToken

import project
from project import (
    add_entry,
    create_pass,
    decrypt_field,
    derive_key,
    encrypt_field,
    init_salt,
    load_entries,
    read_salt,
    search_entries,
    verify_master_password,
)


def setup_test_credentials(tmp_path, monkeypatch):
    creds = tmp_path / "credentials"
    passwords = creds / "passwords"
    keys = creds / "keys"
    passwords.mkdir(parents=True)
    keys.mkdir(parents=True)

    monkeypatch.setattr(project, "CREDENTIALS_DIR", str(creds))
    monkeypatch.setattr(project, "PASSWORDS_DIR", str(passwords))
    monkeypatch.setattr(project, "KEYS_DIR", str(keys))
    monkeypatch.setattr(project, "SALT_PATH", str(keys / "salt.key"))
    monkeypatch.setattr(project, "LAST_VAULT_PATH", str(tmp_path / ".last_vault"))


def test_derive_key_is_deterministic():
    salt = b"s" * 16
    assert derive_key(salt, "secret") == derive_key(salt, "secret")
    assert derive_key(salt, "secret") != derive_key(salt, "other")


def test_encrypt_decrypt_round_trip():
    salt = b"x" * 16
    key = derive_key(salt, "master")
    ciphertext = encrypt_field(key, "hello")
    assert decrypt_field(key, ciphertext) == "hello"


def test_create_pass_empty_name():
    assert create_pass("") == "The password file can't be empty!"


def test_create_pass_duplicate(tmp_path, monkeypatch):
    setup_test_credentials(tmp_path, monkeypatch)
    assert create_pass("work") == "Successfully created file named work.json"
    assert create_pass("work") == "There's already a file named work.json!"


def test_add_entry_and_search(tmp_path, monkeypatch):
    setup_test_credentials(tmp_path, monkeypatch)
    init_salt()
    salt = read_salt()
    key = derive_key(salt, "master")
    create_pass("personal")
    add_entry("personal", key, "github.com", "s3cret")
    matches = search_entries("personal", key, "git")
    assert len(matches) == 1
    assert matches[0][1] == "github.com"
    assert matches[0][2] == "s3cret"


def test_verify_master_password_wrong(tmp_path, monkeypatch):
    setup_test_credentials(tmp_path, monkeypatch)
    init_salt()
    salt = read_salt()
    key = derive_key(salt, "correct")
    create_pass("personal")
    add_entry("personal", key, "site", "pass")
    with pytest.raises(InvalidToken):
        verify_master_password("wrong", "personal")


def test_load_entries_missing_file(tmp_path, monkeypatch):
    setup_test_credentials(tmp_path, monkeypatch)
    with pytest.raises(FileNotFoundError):
        load_entries("missing")
