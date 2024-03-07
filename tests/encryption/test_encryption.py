import hashlib

from cryptopian_playground_hantastic.encryption.aes import AES256CBC, AES256CTR


def test_aes256_cbc():
    key = "YzIyMjM1NzUzYTkyNTMwMGFjOTY4ZDRmMjA2YTcxYjM="
    cipher = AES256CBC(key)
    text = "Hello world"
    enc = cipher.encrypt(text)
    print(enc)
    plain = cipher.decrypt(enc)
    print(plain)
    assert text == plain

    password = "4b35f0b7-1ace-4c0a-9deb-b68457969bb8"
    cipher = AES256CBC(password=password)
    text = "Hello world"
    enc = cipher.encrypt(text)
    print(enc)
    plain = cipher.decrypt(enc)
    print(plain)
    assert text == plain


def test_aes256_ctr():
    key = "YzIyMjM1NzUzYTkyNTMwMGFjOTY4ZDRmMjA2YTcxYjM="
    cipher = AES256CTR(key)
    text = "Hello world"
    enc = cipher.encrypt(text)
    print(enc)
    plain = cipher.decrypt(enc)
    print(plain)
    assert text == plain

    password = "4b35f0b7-1ace-4c0a-9deb-b68457969bb8"
    cipher = AES256CTR(password=password)
    text = "Hello world"
    enc = cipher.encrypt(text)
    print(enc)
    plain = cipher.decrypt(enc)
    print(plain)
    assert text == plain


def test_aes256_ctr_2():
    password = "hello_world"
    cipher = AES256CTR(password=password)
    text = "4b35f0b7-1ace-4c0a-9deb-b68457969bb8"
    enc = cipher.encrypt(text)
    print(enc)
    plain = cipher.decrypt(enc)
    print(plain)
    assert text == plain

    text = "179abee5-9a08-4d83-bfcd-1c4b69072388"
    enc = cipher.encrypt(text)
    print(enc)
    plain = cipher.decrypt(enc)
    print(plain)
    assert text == plain


def test_sha256():
    print(hashlib.sha256(b"79e4c904-843b-4ed9-b50f-e95d696f65cd").hexdigest())
