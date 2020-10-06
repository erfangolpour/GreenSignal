import base64
import hashlib
import random
from Crypto import Random
from Crypto.Cipher import AES

key = '0123456789abcdef'


class AESCipher(object):

    def __init__(self, key): 
        self.key = hashlib.sha256(key.encode('utf-8')).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def encrypt_file(self, filename, chunksize = 64 * 1024):
        iv = Random.new().read(AES.block_size)
        encryptor = AES.new(self.key, AES.MODE_CBC, iv)

        with open(filename, 'rb') as infile:
            result = iv

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += (' ' * (16 - len(chunk) % 16)).encode('utf-8')

                result += encryptor.encrypt(chunk)
        
        return result

    def decrypt_file(self, encrypted_file, chunksize = 64 * 1024):
        iv = encrypted_file[:AES.block_size]
        decryptor = AES.new(self.key, AES.MODE_CBC, iv)

        encrypted_file_data = encrypted_file[AES.block_size:]

        result = b''

        for i in range(len(encrypted_file_data)):
            try:
                chunk = encrypted_file_data[chunksize * i:chunksize * (i + 1)]
            except:
                chunk = encrypted_file_data[chunksize * i:]

            if len(chunk) == 0:
                break

            result += decryptor.decrypt(chunk)
            
        return result

    def _pad(self, s):
        return s + ((AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]