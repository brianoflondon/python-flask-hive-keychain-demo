import asyncio
import base64
import json
import os
from enum import Enum
from hashlib import md5
from pprint import pprint
from uuid import UUID, uuid4

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Cryptodome import Random
from Cryptodome.Cipher import AES
from pydantic import BaseModel
from websockets import connect


def bytes_to_key(data, salt, output=48):
    # extended from https://gist.github.com/gsakkis/4546068
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]


def encrypt(message, passphrase):
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(
        b"Salted__" + salt + aes.encrypt(pad(message, AES.block_size))
    )


def decrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]), AES.block_size)


HAS_SERVER = "wss://hive-auth.arcange.eu"
# HAS_SERVER = "wss://p51-server"

HAS_APP_DATA = {
    "name": "python-flask-demo",
    "description": "Demo - HiveAuth from Python",
    "icon": "flaskblog/static/unknown.jpg",
}
HAS_APP_KEY = os.getenv("HAS_APP_KEY")
HAS_AUTH_REQ_SECRET = UUID(os.getenv("HAS_AUTH_REQ_SECRET"))


class HASApp(BaseModel):
    name: str = "python-flask-demo"
    description: str = "Demo - HiveAuth from Python"
    icon: str = "https://api.v4v.app/v1/hive/avatar/v4vapp"


class KeyType(str, Enum):
    posting = "posting"
    active = "active"
    memo = "memo"


class ChannelDataHAS(BaseModel):
    key_type: KeyType = KeyType.posting
    challenge: str


class AuthDataHAS(BaseModel):
    app: HASApp = HASApp()
    token: str | None
    challenge: ChannelDataHAS | None

    def base64(self) -> str:
        return base64.b64encode(self.token.encode("utf-8")).decode("utf-8")


class AuthReqHAS(BaseModel):
    cmd: str = "auth_req"
    account: str
    data: str
    token: str | None
    auth_key: str


class AuthPayloadHAS(BaseModel):
    account: str
    uuid: str
    auth_key: str
    host: str = HAS_SERVER


class EncryptData:
    plain_text: str | None
    key: str
    cipher: AES
    data_bytes: bytes
    cipher_text_bytes: bytes
    cipher_text_b64: str
    iv: str

    def __init__(self, **kwargs):
        """
        My Decryption system
        https://onboardbase.com/blog/aes-encryption-decryption/
        """
        try:
            if "plain_text" in kwargs and "key" in kwargs:
                self.encrypt(plain_text=kwargs["plain_text"], key=kwargs["key"])
            else:
                self.decrypt(
                    cipher_text_bytes=kwargs["cipher_text_bytes"],
                    key=kwargs["key"],
                    iv=kwargs["iv"],
                )
        except KeyError as ex:
            raise KeyError(ex)

    def encrypt(self, plain_text: str, key: UUID):
        self.plain_text = plain_text
        self.key = key
        self.data_bytes = bytes(plain_text, "utf-8")
        self.cipher = AES.new(key.bytes, AES.MODE_CBC)
        # key_bytes, iv = get_key_and_iv(str(key), salt=bytes('0', 'ascii'))
        # self.cipher.iv = iv
        self.cipher_text_bytes = self.cipher.encrypt(
            pad(self.data_bytes, AES.block_size)
        )
        self.iv = self.cipher.iv
        self.cipher_text_b64 = base64.b64encode(self.cipher_text_bytes).decode("utf-8")

    def decrypt(self, cipher_text_bytes: bytes, key: UUID, iv: str):
        self.cipher_text_bytes = cipher_text_bytes
        self.cipher_text_b64 = base64.b64encode(self.cipher_text_bytes).decode("utf-8")
        self.key = key
        self.iv = iv
        self.cipher = AES.new(key.bytes, AES.MODE_CBC, iv=iv)
        check_data_bytes = self.cipher.decrypt(self.cipher_text_bytes)
        self.plain_text = (unpad(check_data_bytes, AES.block_size)).decode("utf-8")


async def hello(uri):
    auth_key_uuid = uuid4()
    auth_key_uuid = UUID(os.getenv("HAS_AUTH_REQ_SECRET"))
    auth_key = auth_key_uuid.bytes
    session_token = uuid4()
    auth_data = AuthDataHAS()
    data_str = json.dumps(auth_data.json())

    encrypted_payload = EncryptData(plain_text=data_str, key=auth_key_uuid)
    decrypted_payload = EncryptData(
        cipher_text_bytes=encrypted_payload.cipher_text_bytes,
        key=auth_key_uuid,
        iv=encrypted_payload.iv,
    )
    if encrypted_payload.cipher_text_b64 == decrypted_payload.cipher_text_b64:
        print("Encrypted payload pass")
        print("-" * 50)

    auth_key_to_send_bad = EncryptData(
        plain_text=str(auth_key_uuid), key=HAS_AUTH_REQ_SECRET
    )

    payload_base64 = base64.b64encode(data_str.encode("utf-8"))

    encrypted_payload = encrypt(payload_base64, auth_key_uuid.bytes)
    b64_encrypted_payload = base64.b64encode(encrypted_payload).decode("utf-8")

    encrypted_auth_key = encrypt(auth_key_uuid.bytes, HAS_AUTH_REQ_SECRET.bytes)
    b64_encrypted_auth_key = base64.b64encode(encrypted_auth_key).decode("utf-8")

    auth_req = AuthReqHAS.parse_obj(
        {
            "account": "v4vapp.dev",
            "data": b64_encrypted_payload,
            "auth_key": b64_encrypted_auth_key,
        }
    )

    async with connect(uri) as websocket:
        await websocket.send("Let's get this party started!")
        msg = await websocket.recv()
        fails = await websocket.recv()  # need this failure
        pprint(json.loads(msg))
        await websocket.send(auth_req.json())
        msg = await websocket.recv()
        auth_wait = json.loads(msg)
        pprint(json.loads(msg))

        auth_payload = AuthPayloadHAS.parse_obj(
            {
                "account": "v4vapp.dev",
                "uuid": auth_wait["uuid"],
                "auth_key": b64_encrypted_auth_key,
                # "auth_key": base64.b64encode(test_encrypt).decode("utf-8"),
            }
        )
        pprint(json.dumps(auth_payload, default=str, indent=2))
        auth_payload_base64 = base64.b64encode((auth_payload.json()).encode()).decode(
            "utf-8"
        )
        qr_text = f"has://auth_req/{auth_payload_base64}"
        print(qr_text)


asyncio.run(hello(HAS_SERVER))
