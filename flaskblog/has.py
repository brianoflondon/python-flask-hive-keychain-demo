import asyncio
import base64
import json
from uuid import uuid4

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
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


class HASApp(BaseModel):
    name: str = "python-flask-demo"
    description: str = "Demo - HiveAuth from Python"
    icon: str = "https://api.v4v.app/v1/hive/avatar/v4vapp"


class HASAuthData(BaseModel):
    app: HASApp = HASApp()
    token: str = uuid4()
    challenge: str = ""

    def base64(self) -> str:
        return base64.b64encode(self.token.encode("utf-8")).decode("utf-8")


class HASAuthReq(BaseModel):
    cmd: str = "auth_req"
    account: str
    data: str
    token: str = "9048e8c2-fb06-4d16-b716-a575ea59a990"


class HASAuthPayload(BaseModel):
    account: str
    uuid: str
    key: str
    host: str = HAS_SERVER


async def hello(uri):
    auth_key_uuid = uuid4()
    auth_key = auth_key_uuid.bytes
    session_token = uuid4()
    auth_data = HASAuthData.parse_obj({"token": str(session_token)})
    data_str = json.dumps(auth_data.json())
    data_bytes = bytes(data_str, "utf-8")

    cipher = AES.new(auth_key, AES.MODE_CFB)
    cipher_text = cipher.encrypt(data_bytes)
    iv = cipher.iv

    auth_req = HASAuthReq.parse_obj(
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
        print(msg)
        await websocket.send(auth_req.json())
        msg = await websocket.recv()
        auth_wait = json.loads(msg)
        print(msg)
        auth_payload = HASAuthPayload.parse_obj(
            {
                "account": "v4vapp.dev",
                "uuid": auth_wait["uuid"],
                "key": str(auth_key_uuid),
            }
        )
        print(auth_payload)
        auth_payload_base64 = base64.b64encode((auth_payload.json()).encode()).decode("utf-8")
        qr_text = f"has://auth_req/{auth_payload_base64}"
        print(qr_text)


asyncio.run(hello(HAS_SERVER))
