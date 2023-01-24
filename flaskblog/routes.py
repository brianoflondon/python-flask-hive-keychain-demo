import json
import logging
import time
from binascii import hexlify, unhexlify

import requests
from beem.account import Account
from beemgraphenebase.account import PublicKey
from beemgraphenebase.ecdsasig import verify_message
from flask import (
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from flaskblog import app
from flaskblog.forms import LoginForm
from flaskblog.models import User


@app.route("/home", strict_slashes=False)
@app.route("/")
def home():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))

    return render_template("home.html", posts=current_user.get_blog(limit=10))


@app.route("/about")
def about():
    return render_template("about.html", title="About")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = LoginForm()
    return render_template("login.html", title="Login", form=form)


@app.route("/hive/login", methods=["GET", "POST"])
def hive_login():
    """Handle the answer from the Hive Keychain browser extension"""
    logging.info(f"{request.method}")
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST" and request.data:
        logging.info(f"{request.data}")
        ans = json.loads(request.data.decode("utf-8"))
        logging.info(ans)
        if ans["success"] and validate_hivekeychain_ans(ans):
            acc_name = ans["data"]["username"]
            user = User(account=acc_name)
            if user:
                login_user(user, remember=True)
                flash(f"Welcome back - @{user.name}", "info")
                app.logger.info(f"{acc_name} logged in successfully")
                return make_response({"loadPage": url_for("home")}, 200)
                # return redirect(url_for('podcaster.dashboard'))
            else:
                user = User(username=acc_name)
                flash(f"Welcome - @{user.username}", "info")
                app.logger.info(f"{acc_name} logged in for the first time")
                return make_response({"loadPage": url_for("home")}, 200)
                # return redirect(url_for('podcaster.dashboard'))
        else:
            flash("Not Authorised", "danger")
            return make_response({"loadPage": url_for("login")}, 401)


def validate_hivekeychain_ans(ans):
    """takes in the answer from hivekeychain and checks everything"""
    """ https://bit.ly/keychainpython """

    acc_name = ans["data"]["username"]
    pubkey = PublicKey(ans["publicKey"])
    enc_msg = ans["data"]["message"]
    signature = ans["result"]

    msgkey = verify_message(enc_msg, unhexlify(signature))
    pk = PublicKey(hexlify(msgkey).decode("ascii"))
    if str(pk) == str(pubkey):
        app.logger.info(f"{acc_name} SUCCESS: signature matches given pubkey")
        acc = Account(acc_name, lazy=True)
        match = False, 0
        for key in acc["posting"]["key_auths"]:
            match = match or ans["publicKey"] in key
        if match:
            app.logger.info(f"{acc_name} Matches public key from Hive")
            mtime = json.loads(enc_msg)["timestamp"]
            time_since = time.time() - mtime
            if time_since < 30:
                app.logger.info(f"{acc_name} SUCCESS: in {time_since} seconds")
                return True, time_since
            else:
                app.logger.warning(f"{acc_name} ERROR: answer took too long.")
    else:
        app.logger.warning(f"{acc_name} ERROR: message was signed with a different key")
        return False, 0


@app.route("/lookup", methods=["GET", "POST"])
def autocomplete_hive_acc_name():
    """Lookup a Hive account for autocomplete"""
    """ https://api.jqueryui.com/autocomplete/#option-source """
    node = "https://hive.roelandp.nl"
    # node = 'https://api.hive.blog'
    if "term" in request.args:
        search = request.args["term"]
        limit = request.args.get("limit")
        if not limit:
            limit = 10
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            "jsonrpc": "2.0",
            "method": "database_api.list_accounts",
            "params": {"start": search, "limit": limit, "order": "by_name"},
            "id": 1,
        }
        r = requests.post(url=node, data=json.dumps(payload), headers=headers)
        names = [n["name"] for n in r.json()["result"]["accounts"]]
    else:
        names = []
    return make_response(jsonify(names))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@login_required
@app.route("/@<hive_acc>")
def profile(hive_acc: str = ""):
    return render_template("account.html", title="Account")
