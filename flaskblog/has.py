import asyncio
import base64
import json
import os
from enum import Enum
from uuid import uuid4

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pydantic import BaseModel
from websockets import connect

HAS_SERVER = "wss://hive-auth.arcange.eu"
# HAS_SERVER = "wss://p51-server"

HAS_APP_DATA = {
    "name": "python-flask-demo",
    "description": "Demo - HiveAuth from Python",
    "icon": "flaskblog/static/unknown.jpg",
}
APP_KEY = uuid4()

HAS_AUTH_REQ_SECRET = os.getenv("HAS_AUTH_REQ_SECRET")


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
    token: str = "9048e8c2-fb06-4d16-b716-a575ea59a990"
    auth_key: str | None


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

    def __init__(self, plain_text: str, key: str):
        self.plain_text = plain_text
        self.key = key
        self.data_bytes = bytes(plain_text, "utf-8")
        self.cipher = AES.new(key.bytes, AES.MODE_CBC)
        self.cipher_text_bytes = self.cipher.encrypt(
            pad(self.data_bytes, AES.block_size)
        )
        self.iv = self.cipher.iv
        self.cipher_text_b64 = base64.b64encode(self.cipher_text_bytes).decode("utf-8")

        decrypt_cipher = AES.new(key.bytes, AES.MODE_CBC, iv=self.cipher.iv)
        check_data_bytes = decrypt_cipher.decrypt(self.cipher_text_bytes)
        check_plain_text = (unpad(check_data_bytes, AES.block_size)).decode("utf-8")
        if check_plain_text != self.plain_text:
            raise Exception("Bad encryptions")


def my_encrypt_AES_CBC(key: str, data_bytes: bytes) -> EncryptData:
    """
    My Encryption system
    https://onboardbase.com/blog/aes-encryption-decryption/
    """
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(data_bytes, AES.block_size))
    iv = cipher.iv
    return EncryptData(data_bytes=data_bytes, cipher_text=cipher_text, iv=iv)


def my_decryption_AEC_CBC(key: str, iv: str, cipher_text: str):
    """
    My Decryption system
    https://onboardbase.com/blog/aes-encryption-decryption/
    """
    decrypt_cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    plain_text = decrypt_cipher.decrypt(cipher_text)
    return plain_text


async def hello(uri):
    auth_key_uuid = uuid4()
    auth_key = auth_key_uuid.bytes
    session_token = uuid4()
    auth_data = AuthDataHAS.parse_obj({"token": str(session_token)})
    data_str = json.dumps(auth_data.json())

    encrypted_payload = EncryptData(plain_text=data_str, key=auth_key_uuid)
    print(encrypted_payload.cipher_text_b64)

    data_bytes = bytes(data_str, "utf-8")

    cipher = AES.new(auth_key, AES.MODE_CFB)
    cipher_text = cipher.encrypt(data_bytes)
    iv = cipher.iv

    auth_req = AuthReqHAS.parse_obj(
        {
            "account": "v4vapp.dev",
            "data": base64.b64encode(cipher_text).decode("utf-8"),
        }
    )

    decrypt_cipher = AES.new(auth_key, AES.MODE_CFB, iv=iv)
    plain_text = decrypt_cipher.decrypt(cipher_text)
    if data_str == plain_text.decode():
        print("pass encryption")

    async with connect(uri) as websocket:
        await websocket.send("Let's get this party started!")
        msg = await websocket.recv()
        fails = await websocket.recv()  # need this failure
        print(json.dumps(msg, indent=2))
        await websocket.send(auth_req.json())
        msg = await websocket.recv()
        auth_wait = json.loads(msg)
        print(json.dumps(msg, indent=2))
        auth_payload = AuthPayloadHAS.parse_obj(
            {
                "account": "v4vapp.dev",
                "uuid": auth_wait["uuid"],
                "auth_key": base64.b64encode(cipher_text).decode("utf-8"),
            }
        )
        print(json.dumps(auth_payload, default=str, indent=2))
        auth_payload_base64 = base64.b64encode((auth_payload.json()).encode()).decode(
            "utf-8"
        )
        qr_text = f"has://auth_req/{auth_payload_base64}"
        print(qr_text)


asyncio.run(hello(HAS_SERVER))
