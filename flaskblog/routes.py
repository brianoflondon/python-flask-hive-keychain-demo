import json
import logging
import time
from binascii import hexlify, unhexlify
from datetime import timedelta

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
from pydantic import BaseModel
from websockets import connect

from flaskblog import app
from flaskblog.forms import LoginForm
# from flaskblog.has import HASAuthentication
from flaskblog.hivevalidation import (
    SignedAnswer,
    SignedAnswerData,
    validate_hivekeychain_ans,
)
from flaskblog.models import User

HAS_SERVER = "wss://hive-auth.arcange.eu"


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


@app.route("/hive/haslogin", methods=["POST"])
async def has_login():
    logging.info("HAS Login")
    logging.debug(f"{request.data}")
    if request.method == "POST" and request.data:
        logging.info(f"{request.data}")
        ans = json.loads(request.data.decode("utf-8"))
        # flash("Authorised", "danger")
        acc_name = ans.get("acc_name")
        user = User(account=acc_name, login_type="has")
        if user:
            has = HASAuthentication(
                hive_acc=acc_name,
                uri=HAS_SERVER,
                challenge_message="Any string message goes here",
            )
            async with connect(has.uri) as has.websocket:
                time_to_wait = await has.connect_with_challenge()
                await has.get_qrcode()

            if user:
                login_user(user, remember=True, duration=timedelta(days=10))
                flash(f"Welcome back - @{user.name}", "info")
                app.logger.info(f"{acc_name} logged in successfully")

            return render_template("has.html", title="Login")


@app.route("/hive/login", methods=["GET", "POST"])
def hive_login():
    """Handle the answer from the Hive Keychain browser extension"""
    logging.info(f"{request.method}")
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST" and request.data:
        logging.info(f"{request.data}")
        ans = json.loads(request.data.decode("utf-8"))
        signed_answer = SignedAnswer.parse_obj(ans)
        logging.info(ans)
        if signed_answer.success:
            verification = validate_hivekeychain_ans(signed_answer)
            if verification.success:
                acc_name = verification.acc_name
                user = User(account=acc_name, login_type="keychain")
                if user:
                    login_user(user, remember=True, duration=timedelta(days=10))
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


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@login_required
@app.route("/@<hive_acc>")
def profile(hive_acc: str = ""):
    return render_template("account.html", title="Account")
