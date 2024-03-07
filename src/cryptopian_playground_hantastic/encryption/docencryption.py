from typing import Dict
from jsonpath_ng import parse

from .encryption import Encryption, EncryptionMethod
from .aes import AES256CBC, AES256CTR


def create(method, *args, **kwargs) -> Encryption:
    if method == EncryptionMethod.aes256ctr:
        return AES256CTR(*args, **kwargs)
    if method in [EncryptionMethod.aes256cbc]:
        return AES256CBC(*args, **kwargs)
    raise NotImplementedError()


class DocEncryptionConst:
    encryptionMethod = 'encryptionMethod'
    encrypted = 'encrypted'
    default = 'default'


class DocEncryption:
    def __init__(self, credential_config: dict):
        """

        :param credential_config:
{
    "aes256ctr": {
      "password": "abcdefg-1234-8912-4819-fjklbnasioqwe1"
    },
    "aes256cbc": {
      "key": "abcdejfkdlsajfdsbuioqjewrkqlnbx="
    }
}
        """
        self.__encryption_lookup: Dict[str, Encryption] = {}
        for key, value in credential_config.items():
            if key == DocEncryptionConst.default:
                self.default_method = value
                continue
            self.__encryption_lookup[key] = create(method=key, **value)
        if DocEncryptionConst.default not in credential_config:
            self.default_method = list(self.__encryption_lookup.keys())[0]

    def _get_encryption(self, encryption_method):
        if encryption_method is None:
            encryption_method = self.default_method
        return self.__encryption_lookup[encryption_method]

    def encrypt(self, doc, fields_to_encrypt, encryption_method=None):
        encryptor = self._get_encryption(encryption_method)
        encrypted = doc.get(DocEncryptionConst.encrypted, [])
        changed = False
        for field in fields_to_encrypt:
            if field in encrypted:
                continue
            jsonpath_exp = parse(field)
            for match in jsonpath_exp.find(doc):
                field_encrypted = encryptor.encrypt(match.value)
                self._set_field_value(match, field_encrypted)
                encrypted.append(str(match.full_path))
                changed = True
        if changed:
            doc[DocEncryptionConst.encrypted] = encrypted
            doc[DocEncryptionConst.encryptionMethod] = encryptor.method
        return changed

    def decrypt(self, doc):
        encryption_method = doc.get(DocEncryptionConst.encryptionMethod, 'aes256ctr')
        encryptor = self._get_encryption(encryption_method)
        encrypted = doc.get(DocEncryptionConst.encrypted, [])
        for field in list(encrypted):  # make a copy because encrypted will be modified
            jsonpath_exp = parse(field)
            for match in jsonpath_exp.find(doc):
                field_plain = encryptor.decrypt(match.value)
                encrypted.remove(field)
                self._set_field_value(match, field_plain)
        assert encrypted == []
        if DocEncryptionConst.encrypted in doc:
            del doc[DocEncryptionConst.encrypted]
        if DocEncryptionConst.encryptionMethod in doc:
            del doc[DocEncryptionConst.encryptionMethod]
        return doc

    @staticmethod
    def _set_field_value(match, field_value):
        match.context.value[match.path.fields[0]] = field_value

    def update_encryption_method(self, doc: dict, new_encryption_method: str):
        encryption_method = doc[DocEncryptionConst.encryptionMethod]
        if encryption_method == new_encryption_method:
            return None
        encryptor = self._get_encryption(encryption_method)
        new_encryptor = self.__encryption_lookup[new_encryption_method]

        encrypted = doc.get(DocEncryptionConst.encrypted, [])
        for field in encrypted:
            jsonpath_exp = parse(field)
            for match in jsonpath_exp.find(doc):
                field_plain = encryptor.decrypt(match.value)
                field_encrypted = new_encryptor.encrypt(field_plain)
                field_decrypted = new_encryptor.decrypt(field_encrypted)
                assert field_decrypted == field_plain
                self._set_field_value(match, field_encrypted)

        doc[DocEncryptionConst.encryptionMethod] = new_encryption_method
        return doc
