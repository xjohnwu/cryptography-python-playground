from abc import ABC, abstractmethod


class EncryptionMethod:
    aes256ctr = 'aes256ctr'  # current default
    aes256cbc = 'aes256cbc'


class Encryption(ABC):
    method: str

    @abstractmethod
    def decrypt(self, encrypted):
        raise NotImplementedError()

    @abstractmethod
    def encrypt(self, plain):
        raise NotImplementedError()
