import copy

from cryptopian_playground_hantastic.encryption import DocEncryption
from cryptopian_playground_hantastic.encryption.docencryption import DocEncryptionConst


class TestDocEncryption:
    def setup_class(self):
        self.doc_encryption = DocEncryption({
            "aes256ctr": {
                "password": "abcdefg-1234-8912-4819-fjklbnasioqwe1"
            },
            "aes256cbc": {
                "key": "MTFlNZczN2I2ZWJmODPzYTdhOGY2MzJqZjJiOGMxNWH="
            }})
        assert self.doc_encryption.default_method == 'aes256ctr'

    def test_encryption_root_level(self):
        original_doc = {
            "username": "u",
            "password": "p"
        }
        doc = copy.deepcopy(original_doc)
        changed = self.doc_encryption.encrypt(doc, ['password', '*.password'])
        print(doc)
        assert changed
        assert doc['password'] != 'p'
        assert doc[DocEncryptionConst.encrypted] == ['password']
        assert doc[DocEncryptionConst.encryptionMethod] == self.doc_encryption.default_method

        self.doc_encryption.decrypt(doc)
        print(doc)
        assert doc == original_doc

    def test_encryption_child_level(self):
        original_doc = {
            "init_params": {
                "username": "u",
                "password": "p"
            }
        }
        doc = copy.deepcopy(original_doc)
        changed = self.doc_encryption.encrypt(doc, ['password', '*.password'])
        print(doc)
        assert changed
        assert doc['init_params']['password'] != 'p'
        assert doc[DocEncryptionConst.encrypted] == ['init_params.password']
        assert doc[DocEncryptionConst.encryptionMethod] == self.doc_encryption.default_method

        self.doc_encryption.decrypt(doc)
        print(doc)
        assert doc == original_doc

    def test_encryption_root_and_child(self):
        original_doc = {
            "username": "u",
            "password": "p",
            "init_params": {
                "username": "u",
                "password": "p"
            }
        }
        doc = copy.deepcopy(original_doc)
        changed = self.doc_encryption.encrypt(doc, ['password', '*.password'])
        print(doc)
        assert changed
        assert doc['password'] != 'p'
        assert doc['init_params']['password'] != 'p'
        assert doc[DocEncryptionConst.encrypted] == ['password', 'init_params.password']
        assert doc[DocEncryptionConst.encryptionMethod] == self.doc_encryption.default_method

        self.doc_encryption.decrypt(doc)
        print(doc)
        assert doc == original_doc

    def test_update_encryption(self):
        original_doc = {
            "init_params": {
                "username": "u",
                "password": "p"
            }
        }
        doc = copy.deepcopy(original_doc)
        changed = self.doc_encryption.encrypt(doc, ['password', '*.password'])
        print(doc)
        assert changed
        assert doc[DocEncryptionConst.encryptionMethod] == self.doc_encryption.default_method

        self.doc_encryption.update_encryption_method(doc, 'aes256cbc')
        print(doc)
        assert doc[DocEncryptionConst.encryptionMethod] == 'aes256cbc'

        self.doc_encryption.decrypt(doc)
        print(doc)
        assert doc == original_doc
