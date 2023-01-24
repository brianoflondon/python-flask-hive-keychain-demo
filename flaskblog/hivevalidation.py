import json
import logging
from binascii import hexlify, unhexlify
from datetime import datetime, timedelta, timezone
from typing import Any

from beem.account import Account
from beemgraphenebase.account import PublicKey
from beemgraphenebase.ecdsasig import verify_message
from pydantic import BaseModel, Field

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
    # format="{asctime} {levelname} {module} {lineno:>5} : {message}",
    # datefmt="%Y-%m-%dT%H:%M:%S,uuu",
)
AUTHENTICATION_TIME_LIMIT = 60


class SignedAnswerData(BaseModel):
    _type: str = Field(..., alias='type')
    username: str
    message: str
    method: str
    key: str

    def __init__(__pydantic_self__, **data: Any) -> None:
        super().__init__(**data)


class SignedAnswer(BaseModel):
    success: bool = False
    error: str | None
    result: str
    data: SignedAnswerData
    message: str | None  # Message from the server
    request_id: int
    publicKey: str | None

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.publicKey)


class SignedAnswerVerification(BaseModel):
    acc_name: str
    success: bool
    pubkey: str
    elapsed_time: timedelta


def validate_hivekeychain_ans(signed_answer: SignedAnswer) -> SignedAnswerVerification:
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
        logging.info(f"{acc_name} SUCCESS: signature matches given pubkey")
        acc = Account(acc_name, lazy=True)
        match = False, 0
        for key in acc["posting"]["key_auths"]:
            match = match or pubkey_s in key
        if match:
            logging.info(f"{acc_name} Matches public key from Hive")
            mtime = json.loads(enc_msg)["timestamp"]
            elapsed_time = datetime.now(tz=timezone.utc).timestamp() - mtime
            if elapsed_time < AUTHENTICATION_TIME_LIMIT:
                logging.info(f"{acc_name} SUCCESS: in {elapsed_time} seconds")
                return SignedAnswerVerification(
                    acc_name=acc_name,
                    success=True,
                    pubkey=pubkey_s,
                    elapsed_time=elapsed_time,
                )
            else:
                logging.info(f"{acc_name} ERROR: answer took too long.")
                return SignedAnswerVerification(
                    acc_name=acc_name,
                    success=False,
                    pubkey=pubkey_s,
                    elapsed_time=elapsed_time,
                )
    else:
        logging.info(f"{acc_name} ERROR: message was signed with a different key")
        return SignedAnswerVerification(
            acc_name=acc_name, success=False, pubkey=pubkey_s, elapsed_time=elapsed_time
        )
