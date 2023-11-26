from project import create_key, create_pass, load_key


def test_create_key():
    assert create_key("") == "The key can't be empty!"
    with open("existing_key.key", "wb") as _:
        pass
    assert (
        create_key("existing_key") == "There's already a file named existing_key.key!"
    )
    assert create_key("new_key") == "Successfully created file named new_key.key"


def test_create_pass():
    assert create_pass("") == "The password file can't be empty!"
    with open("existing_pass.pass", "wb") as _:
        pass
    assert (
        create_pass("existing_pass")
        == "There's already a file named existing_pass.pass!"
    )
    assert create_pass("new_pass") == "Successfully created file named new_pass.pass"


def test_load_key():
    assert load_key("") == ""
    with open("existing_load_key.key", "wb") as f:
        f.write(b"sample_key")
    assert load_key("existing_load_key") == b"sample_key"
    assert load_key("new_load_key") == None
