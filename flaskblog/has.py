import asyncio
import base64
import json
import os
from binascii import hexlify, unhexlify
from datetime import datetime, timedelta
from enum import Enum
from hashlib import md5
from pprint import pprint
from uuid import UUID, uuid4

from beem.account import Account
from beemgraphenebase.account import PublicKey
from beemgraphenebase.ecdsasig import verify_message

# from Crypto.Cipher import AES
from Cryptodome import Random
from Cryptodome.Cipher import AES
from pydantic import BaseModel
from websockets import connect

BLOCK_SIZE = AES.block_size
# https://stackoverflow.com/questions/35472396/how-does-cryptojs-get-an-iv-when-none-is-specified
# https://gist.github.com/tly1980/b6c2cc10bb35cb4446fb6ccf5ee5efbc
# https://devpress.csdn.net/python/630460127e6682346619ab98.html
HIVE_ACCOUNT = "v4vapp.dev"


class SignedAnswerData(BaseModel):
    answer_type: str
    username: str
    message: str
    method: str
    key: str


class SignedAnswer(BaseModel):
    success: bool = False
    error: str | None
    result: str
    data: SignedAnswerData
    message: str | None  # Message from the server
    request_id: int
    publicKey: str

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.publicKey)


def validate_hivekeychain_ans(signed_answer: SignedAnswer):
    """takes in the answer from hivekeychain and checks everything"""
    """ https://bit.ly/keychainpython """

    acc_name = signed_answer.data.username  # ans["data"]["username"]
    pubkey_s = signed_answer.publicKey  # PublicKey(ans["publicKey"])
    pubkey = signed_answer.public_key
    enc_msg = signed_answer.data.message  # ans["data"]["message"]
    signature = signed_answer.result  # ans["result"]

    msgkey = verify_message(enc_msg, unhexlify(signature))
    pk = PublicKey(hexlify(msgkey).decode("ascii"))
    if str(pk) == str(pubkey):
        print(f"{acc_name} SUCCESS: signature matches given pubkey")
        acc = Account(acc_name, lazy=True)
        match = False, 0
        for key in acc["posting"]["key_auths"]:
            match = match or pubkey_s in key
        if match:
            print(f"{acc_name} Matches public key from Hive")
            mtime = json.loads(enc_msg)["timestamp"]
            time_since = datetime.utcnow().timestamp() - mtime
            if time_since < 30:
                print(f"{acc_name} SUCCESS: in {time_since} seconds")
                return True, time_since
            else:
                print(f"{acc_name} ERROR: answer took too long.")
    else:
        print(f"{acc_name} ERROR: message was signed with a different key")
        return False, 0


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


class ChallengeHAS(BaseModel):
    key_type: KeyType = KeyType.posting
    challenge: str


class AuthDataHAS(BaseModel):
    app: HASApp = HASApp()
    token: str | None
    challenge: ChallengeHAS | None

    @property
    def bytes(self):
        """Return object as json string in bytes"""
        return json.dumps(self.dict()).encode("utf-8")


class AuthReqHAS(BaseModel):
    cmd: str = "auth_req"
    account: str
    data: str
    token: str | None
    auth_key: str


class AuthPayloadHAS(BaseModel):
    host: str = HAS_SERVER
    account: str
    uuid: UUID
    key: UUID


def str_bytes(uuid: UUID) -> bytes:
    return str(uuid).encode("utf-8")


class CmdType(str, Enum):
    auth_wait = "auth_wait"
    auth_ack = "auth_ack"
    auth_nack = "auth_nack"
    auth_err = "auth_err"


class AuthWaitHAS(BaseModel):
    cmd: CmdType
    uuid: UUID
    expire: datetime
    account: str


class AuthAckNakErrHAS(BaseModel):
    cmd: CmdType
    uuid: UUID
    data: str
    auth_key: bytes | None
    auth_data: AuthDataHAS | None
    auth_payload: AuthPayloadHAS | None
    signed_answer: SignedAnswer | None
    validated: bool | None
    time_to_validate: timedelta | None

    @property
    def decrypted_data(self) -> SignedAnswer:
        data_bytes = self.data.encode("utf-8")
        return json.loads(decrypt(data_bytes, self.auth_key).decode("utf-8"))

    def decrypt(self):
        if (
            self.cmd == CmdType.auth_ack
            and self.auth_key
            and self.auth_data
            and self.auth_payload
            and self.data
        ):
            self.signed_answer = SignedAnswer(
                success=True,
                error=None,
                result=self.decrypted_data["challenge"]["challenge"],
                data=SignedAnswerData(
                    answer_type="HAS",
                    username=self.auth_payload.account,
                    message=self.auth_data.challenge.challenge,
                    method=self.auth_data.challenge.key_type,
                    key=self.auth_data.challenge.key_type,
                ),
                request_id=1,
                publicKey=self.decrypted_data["challenge"]["pubkey"],
            )
            self.validated, time_to_validate = validate_hivekeychain_ans(
                self.signed_answer
            )
            self.time_to_validate = timedelta(seconds=time_to_validate)


async def hello(uri):
    auth_key_uuid = uuid4()
    auth_key = str_bytes(auth_key_uuid)

    challenge = ChallengeHAS(
        challenge=json.dumps(
            {
                "timestamp": datetime.utcnow().timestamp(),
                "message": "Can't stop this challenge",
            }
        )
    )
    auth_data = AuthDataHAS(challenge=challenge)
    pprint(auth_data.bytes)

    b64_auth_data_encrypted = encrypt(auth_data.bytes, auth_key)
    pprint(b64_auth_data_encrypted)

    b64_auth_key_encrypted = encrypt(
        str_bytes(auth_key_uuid), str_bytes(HAS_AUTH_REQ_SECRET)
    )
    pprint(b64_auth_key_encrypted)

    auth_req = AuthReqHAS.parse_obj(
        {
            "account": HIVE_ACCOUNT,
            "data": b64_auth_data_encrypted,
            "auth_key": b64_auth_key_encrypted,
        }
    )

    async with connect(uri) as websocket:
        await websocket.send("Let's get this party started!")
        msg = await websocket.recv()
        pprint(json.loads(msg))
        msg2 = await websocket.recv()  # need this failure
        pprint(json.loads(msg2))
        await websocket.send(auth_req.json())
        msg = await websocket.recv()
        auth_wait = AuthWaitHAS.parse_raw(msg)
        pprint(json.loads(msg))

        auth_payload = AuthPayloadHAS(
            account=HIVE_ACCOUNT, uuid=auth_wait.uuid, key=auth_key_uuid
        )

        pprint(json.dumps(auth_payload, default=str, indent=2))
        auth_payload_base64 = base64.b64encode((auth_payload.json()).encode()).decode(
            "utf-8"
        )
        qr_text = f"has://auth_req/{auth_payload_base64}"
        print(qr_text)

        print("-" * 50)

        msg = await websocket.recv()
        auth_ack = AuthAckNakErrHAS.parse_raw(msg)
        auth_ack.auth_key = auth_key
        auth_ack.auth_data = auth_data
        auth_ack.auth_payload = auth_payload
        pprint(auth_ack)
        if auth_ack.uuid == auth_wait.uuid:
            print("uuid OK")
            auth_ack.decrypt()
            if auth_ack.validated:
                pprint(
                    f"Authentication successful in {auth_ack.time_to_validate.seconds:.2f} seconds"
                )



asyncio.run(hello(HAS_SERVER))
