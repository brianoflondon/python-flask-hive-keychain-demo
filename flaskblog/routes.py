from types import MethodDescriptorType
from flask import render_template, url_for, flash, redirect, request
from flaskblog import app, db, bcrypt
from flaskblog.forms import RegistrationForm, LoginForm
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required


# Added for Hive Keychain login
import time
from binascii import hexlify, unhexlify
from beem.account import Account
from beemgraphenebase.account import PublicKey
from beemgraphenebase.ecdsasig import verify_message
from flask import make_response
import json

posts = [
    {
        'author': 'Corey Schafer',
        'title': 'Blog Post 1',
        'content': 'First post content',
        'date_posted': 'April 20, 2018'
    },
    {
        'author': 'Jane Doe',
        'title': 'Blog Post 2',
        'content': 'Second post content',
        'date_posted': 'April 21, 2018'
    }
]

@app.route("/home", strict_slashes=False)
@app.route("/")
def home():
    return render_template('home.html', posts=posts)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/hive/login", methods=['GET','POST'])
def hive_login():
    """ Handle the answer from the Hive Keychain browser extension """
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST' and request.data:
        ans = json.loads(request.data.decode('utf-8'))
        if ans['success'] and validate_hivekeychain_ans(ans):
            acc_name = ans['data']['username']
            user = User.query.filter_by(username = acc_name).first()
            if user:
                login_user(user, remember=True)
                flash(f'Welcome back - @{user.username}', 'info')
                app.logger.info(f'{acc_name} logged in successfully')
                return make_response({'loadPage':url_for('home') }, 200)
                # return redirect(url_for('podcaster.dashboard'))
            else:
                user = User(username=acc_name)
                db.session.add(user)
                db.session.commit()
                result = login_user(user, remember=True)
                flash(f'Welcome - @{user.username}', 'info')
                app.logger.info(f'{acc_name} logged in for the first time')
                return make_response({'loadPage':url_for('home') }, 200)
                # return redirect(url_for('podcaster.dashboard'))
        else:
            flash('Not Authorised','danger')
            return make_response({'loadPage':url_for('login') }, 401)





def validate_hivekeychain_ans(ans):
    """ takes in the answer from hivekeychain and checks everything """
    """ https://bit.ly/keychainpython """

    acc_name = ans['data']['username']
    pubkey = PublicKey(ans['publicKey'])
    enc_msg = ans['data']['message']
    signature = ans['result']

    msgkey = verify_message(enc_msg, unhexlify(signature))
    pk = PublicKey(hexlify(msgkey).decode("ascii"))
    if str(pk) == str(pubkey):
        app.logger.info(f'{acc_name} SUCCESS: signature matches given pubkey')
        acc = Account(acc_name, lazy=True)
        match = False, 0
        for key in acc['posting']['key_auths']:
            match = match or ans['publicKey'] in key
        if match:
            app.logger.info(f'{acc_name} Matches public key from Hive')
            mtime = json.loads(enc_msg)['timestamp']
            time_since = time.time() - mtime
            if time_since < 30:
                app.logger.info(f'{acc_name} SUCCESS: in {time_since} seconds')
                return True , time_since
            else:
                app.logger.warning(f'{acc_name} ERROR: answer took too long.')
    else:
        app.logger.warning(f'{acc_name} ERROR: message was signed with a different key')
        return False, 0





@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')
