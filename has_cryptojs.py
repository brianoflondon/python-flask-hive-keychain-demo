import base64
import json
from hashlib import md5
from uuid import uuid4

from Cryptodome import Random
from Cryptodome.Cipher import AES

BLOCK_SIZE = 16
# https://stackoverflow.com/questions/35472396/how-does-cryptojs-get-an-iv-when-none-is-specified
# https://gist.github.com/tly1980/b6c2cc10bb35cb4446fb6ccf5ee5efbc
# https://devpress.csdn.net/python/630460127e6682346619ab98.html


def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + (chr(length) * length).encode()


def unpad(data):
    return data[: -(data[-1] if type(data[-1]) == int else ord(data[-1]))]


def bytes_to_key(data: bytes, salt: bytes, output: int = 48) -> bytes:
    # extended from https://gist.github.com/gsakkis/4546068
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]


def encrypt(message: bytes, passphrase: bytes) -> bytes:
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))


def decrypt(encrypted: bytes, passphrase: bytes):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))


password = "some password".encode()
ct_b64 = "U2FsdGVkX1+ATH716DgsfPGjzmvhr+7+pzYfUzR+25u0D7Z5Lw04IJ+LmvPXJMpz"

test = "U2FsdGVkX19W4fpKOWxctln3l2h7sfUAALH9GPEUHUZi1jtJgWCY7Q0RDxDiAakL"


print(base64.b64decode(ct_b64))

pt = decrypt(ct_b64, password)
print("pt", pt)

print("pt", decrypt(encrypt(pt, password), password))

web = "U2FsdGVkX1+s3npHz/wVFmcpPeBHVq1Gh023rwUyFK4Jpk8eJVqXKwbdh0NCzC0C"

print(decrypt(web, password))

msg = {"a": "1", "b": "2"}
password2 = uuid4()
print("password2", password2)
msg_b = json.dumps(msg).encode("utf-8")
print(msg_b)
print(encrypt(msg_b, str(password2).encode()))

# testing:
# https://stackblitz.com/edit/cryptojs-aes-encrypt-decrypt?file=index.js
