{
    "success": True,
    "error": None,
    "result": "207cb3c0dca216d1fe403ea6c8471ab1554206d00623126db4cf3cad7a453336c94228ad536d56ee2a400d1ee358514ca8b832837a6f6a436d0c39478a6d69a318",
    "data": {
        "type": "signBuffer",
        "username": "v4vapp",
        "message": '{"signed_message":{"type":"login","address":"v4vapp","page":"http://10.0.0.243:5050/login"},"timestamp":1673678373}',
        "method": "Posting",
        "key": "posting",
    },
    "message": "Message signed succesfully.",
    "request_id": 1,
    "publicKey": "STM7qQtcXDoooAPQtjJBDoCLktRQ3LkFUqwauaPhLGVFttZaPBbtf",
}


class SignedAnswerData:
    answer_type: str
    username: str
    message: str
    method: str
    key: str


class SignedAnswer:
    success: bool
    error: str | None
    result: str
    data: SignedAnswerData
    message: str
    request_id: int
    publicKey: str

# HAS challenge response
{
    "token": "968eab65-46c3-409d-ae23-52875cf5be07",
    "expire": 1673772352207,
    "challenge": {
        "pubkey": "STM78UwFNbRniNJWpN8CuGe6nhfNJYVQ4Sba2DGyJCWzhK1XkdMMu",
        "challenge": "207a5a545a7be26298b604321f9d00f5062ff65db8bb89a1487a99c7923367492843c284e5b0320de9d8f1e180a4116fcefe687fd99e86ff3b256f362cce3aeb42",
    },
}

# challenge.challenge in HAS is signature result in KeyChain.
#

# Keychain challenge response
{
    "success": True,
    "error": None,
    "result": "1f387624f40b99c53359fadf0b1fed15d40c290cb83d3f3fe8885c316d5f576c697bfccae633ce0e930cce6d43f7dc8722046917812bfd105563e3344a8cec674d",
    "data": {
        "type": "signBuffer",
        "username": "brianoflondon",
        "message": '{"signed_message":{"type":"login","address":"brianoflondon","page":"http://10.0.0.243:5050/login"},"timestamp":1673695059}',
        "method": "Posting",
        "key": "posting",
    },
    "message": "Message signed succesfully.",
    "request_id": 1,
    "publicKey": "STM7B1eanwUQhXa8tdabTi2RxHnXWtyMBd6iJDZ3Z2QA6rKHQY2WJ",
}
