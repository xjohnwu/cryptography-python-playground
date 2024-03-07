#!/usr/bin/env python3                                                                               
# -*- coding: utf-8 -*-                                                                              
# @author: zig(zig@uranome.com)

import base64
import binascii
import hashlib

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter

from .encryption import Encryption, EncryptionMethod


class AES256CBC(Encryption):
    method = EncryptionMethod.aes256cbc
    bs = AES.block_size

    def __init__(self, key=None, password=None):
        if password is not None:
            self.key = hashlib.sha256(password.encode()).digest()
        else:
            self.key = base64.b64decode(key)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    @staticmethod
    def _pad(s, bs):
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    def encrypt(self, plain):
        raw = self._pad(plain, self.bs)
        iv = Random.new().read(self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode())).decode()

    def decrypt(self, encrypted):
        encrypted = base64.b64decode(encrypted)
        iv = encrypted[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain = cipher.decrypt(encrypted[self.bs:])
        return self._unpad(plain).decode()


class AES256CTR(Encryption):
    method = EncryptionMethod.aes256ctr
    # AES supports multiple key sizes: 16 (AES128), 24 (AES192), or 32 (AES256).
    key_bytes = 32
    bs = AES.block_size

    def __init__(self, password):
        self.key = hashlib.sha256(password.encode()).digest()

    def encrypt(self, plaintext):
        assert len(self.key) == self.key_bytes

        # Choose a random, 16-byte IV.
        iv = Random.new().read(self.bs)

        # Convert the IV to a Python integer.
        iv_int = int(binascii.hexlify(iv), 16)

        # Create a new Counter object with IV = iv_int.
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

        # Create AES-CTR cipher.
        aes = AES.new(self.key, AES.MODE_CTR, counter=ctr)

        # Encrypt and return IV and ciphertext.
        return base64.b64encode(iv + aes.encrypt(plaintext.encode())).decode()

    def decrypt(self, encrypted):
        assert len(self.key) == self.key_bytes
        encrypted = base64.b64decode(encrypted)

        iv = encrypted[:self.bs]
        # Initialize counter for decryption. iv should be the same as the output of encrypt().
        iv_int = int(binascii.hexlify(iv), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

        # Create AES-CTR cipher.
        aes = AES.new(self.key, AES.MODE_CTR, counter=ctr)

        # Decrypt and return the plaintext.
        return aes.decrypt(encrypted[self.bs:]).decode()
