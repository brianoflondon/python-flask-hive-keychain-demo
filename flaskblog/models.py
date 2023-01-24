import json
from datetime import datetime
from typing import Dict, Union

from beem.account import Account
from flask_login import UserMixin

from flaskblog import login_manager


@login_manager.user_loader
def load_user(account: str):
    try:
        return User(account)
    except:
        return None


class User(Account, UserMixin):
    # Changed the nullable fields for password and email
    # username can be the Hive username

    def get_id(self):
        try:
            return self.name
        except AttributeError:
            return None

    @property
    def profile(self) -> Union[Dict, None]:
        try:
            posting_json_metadata = json.loads(self.get("posting_json_metadata"))
            return posting_json_metadata["profile"]
        except KeyError:
            return None

    def __repr__(self):
        try:
            posting_json_metadata = json.loads(self.get("posting_json_metadata"))
            profile_name = posting_json_metadata["profile"]["name"]
        except KeyError:
            profile_name = ""
        return f"{self.name} - {profile_name}"

    def json_posting_json_metadata(self):
        return json.dumps(self.posting_json_metadata, indent=2)
