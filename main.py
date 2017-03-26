from flask import Flask
from flask import request, redirect, session, render_template, flash, url_for
from flask_bootstrap import Bootstrap
import hashlib
import urllib
import json
import redis
import uuid
import yaml
from Crypto import Random
from Crypto.Cipher import AES
import base64

app = Flask(__name__)
Bootstrap(app)
r = redis.StrictRedis()

with open("app_config.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)

app.secret_key = cfg['app']['secretkey']
postapikey = cfg['app']['postapikey']
ttl = cfg['users']['timeout']
ntries = cfg['users']['ntries']
nattempts = cfg['users']['nattempts']

# Some crypto staff

BLOCK_SIZE = 16


def trans(key):
    return hashlib.md5(key.encode("utf-8")).digest()


def encrypt(message, passphrase):
    passphrase = trans(passphrase)
    IV = Random.new().read(BLOCK_SIZE)
    aes = AES.new(passphrase, AES.MODE_CFB, IV)
    return base64.b64encode(IV + aes.encrypt(message)).decode("utf-8")


def decrypt(encrypted, passphrase):
    passphrase = trans(passphrase)
    encrypted = base64.b64decode(encrypted)
    IV = encrypted[:BLOCK_SIZE]
    aes = AES.new(passphrase, AES.MODE_CFB, IV)
    return aes.decrypt(encrypted[BLOCK_SIZE:]).decode("utf-8")


def calc_sha256(block):
    sha256 = hashlib.sha256()
    sha256.update(block.encode("utf-8"))
    return sha256.hexdigest()


def mokum_auth(apikey):
    try:
        req = urllib.request.Request("https://mokum.place/api/v1/whoami.json")
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        req.add_header('X-API-Token', apikey)
        resp = urllib.request.urlopen(req)
        message = json.loads(resp.read().decode("utf8"))
        if message["user"]["name"]:
            return message["user"]["name"]
    except:
        return False


def mokum_check(uname):
    try:
        req = urllib.request.Request("https://mokum.place/" + uname)
        urllib.request.urlopen(req)
        return True
    except:
        return False


def mokum_message(user, message):
    try:
        postdata = {"post": {"timelines": ["direct:" + user],
                             "text": message,
                             "comments_disabled": True,
                             "nsfw": False},
                    "_uuid": str(uuid.uuid4())}

        # print (json.dumps(postdata))

        req = urllib.request.Request("https://mokum.place/api/v1/posts.json")
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        req.add_header('X-API-Token', postapikey)

        resp = urllib.request.urlopen(req, json.dumps(postdata).encode("utf-8"))

        return True
    except Exception as e:
        print(e)
        return False


def crush_num(login):
    try:
        return len(r.lrange(login, 0, -1))
    except:
        return 0


def crush_check(login, crush):
    for i in r.lrange(login, 0, -1):

        if str(calc_sha256(crush)) == i.decode("utf-8"):
            r.lrem(login, 0, i)
            return True
    return False


def crush_add(login, crush):
    for i in r.lrange(crush, 0, -1):
        if str(calc_sha256(login)) == i.decode("utf-8"):
            return False
    r.lpush(crush, calc_sha256(login))
    return True


def crush_stat(login, crush):
    for i in r.lrange(crush, 0, -1):
        if str(calc_sha256(login)) == i.decode("utf-8"):
            return True
    return False


def crush_addtry(login, crush):
    try:
        for i in r.lrange(login + "+tries", 0, -1):
            if decrypt(i, login) == crush:
                return True
        r.lpush(login + "+tries", encrypt(crush, login))
    except Exception as e:
        print(e)
        r.lpush(login + "+tries", encrypt(crush, login))
    return True


def crush_deltry(login, crush):
    try:
        for i in r.lrange(login + "+tries", 0, -1):
            if decrypt(i, login) == crush:
                r.lrem(login + "+tries", 0, i)
                return True
    except Exception as e:
        print(e)
        return False

    return False


def crush_addmutual(login, crush):
    try:
        for i in r.lrange(login + "+mutual", 0, -1):
            if decrypt(i, login) == crush:
                return True
        r.lpush(login + "+mutual", encrypt(crush, login))
    except:
        r.lpush(login + "+mutual", encrypt(crush, login))
    return True


def crush_delmutual(login, crush):
    try:
        for i in r.lrange(login + "+mutual", 0, -1):
            if decrypt(i, login) == crush:
                r.lrem(login + "+mutual", 0, i)
                return True
    except:
        return False

    return False


def crush_ismutal(login, crush):
    try:
        for i in r.lrange(login + "+mutual", 0, -1):
            if decrypt(i, login) == crush:
                return True
    except:
        return False
    return False


# TODO:
# Nm, [18.03.17 16:42]
# Your mutal crushes are with .
# наверное, не надо эту строку показывать, если нет mutual crushes (и опечатка, btw)
# и с You have sent crushes to . то же самое
# или You haven't sent any


def crush_mutual(login):
    mutualcrushes = []
    try:
        for i in r.lrange(login + "+mutual", 0, -1):
            mutualcrushes.append("@" + decrypt(i, login))
    except:
        mutualcrushes = ["No one yet"]
    return mutualcrushes


def crush_sent(login):
    sentcrushes = []
    try:
        for i in r.lrange(login + "+tries", 0, -1):
            sentcrushes.append("@" + decrypt(i, login))
    except:
        sentcrushes = ["no one :("]
    return sentcrushes


def crush_tries(login, incr=0):
    # init attempt counter
    try:
        attempt = int(r.get(login + "+attempt"))
    except:
        attempt = 1
        r.setex(login + "+attempt", ttl * 10, 1)

    try:
        tries = int(r.get(login + "+count"))
    except:
        if attempt > 0:
            tries = int(ntries / attempt)
        else:
            tries = 0
        if attempt < nattempts:
            attempt += 1
        r.setex(login + "+attempt", ttl * 10, attempt)
        r.setex(login + "+count", ttl, tries)

    if incr != 0:
        tries -= incr
        if tries < 0:
            tries = 0
        r.setex(login + "+attempt", ttl * 10, attempt)
        r.setex(login + "+count", ttl, tries)

    return tries


@app.route('/')
def process():
    guessorfail = ""
    if 'login' in session:
        login = session['login']

        tries = crush_tries(login)

        if 'crushflash' in session:
            guessorfail = session['crushflash']
            # print(session)
            del session['crushflash']

        if len(guessorfail) > 0:
            flash(guessorfail)

        return render_template('main.html', login=login, num=crush_num(login), guess="", tries=tries,
                               mutual=crush_mutual(login), sent=crush_sent(login))
    else:
        return render_template('login.html')


@app.route('/guessortry', methods=['POST'])
def makeguess():
    guessorfail = ""

    if 'login' in session:
        login = str(session['login']).lower()
        crush = request.form['crush']
        crush = crush.strip()
        if len(crush) > 0:
            if (request.form['submit'] == 'Check!'):
                # print("check")
                if (crush_stat(login, crush)):
                    guessorfail = "You have already sent your crush to @" + crush + " ."
                    crush_addtry(login, crush)
                elif crush_ismutal(login, crush):
                    guessorfail = "You already have a mutual crush with @" + crush + " , why are you checking? :)"
                else:
                    guessorfail = "You haven't sent any crushes to @" + crush + " ,  so do make a try!"

            elif mokum_check(crush):
                if crush_tries(login) > 0:
                    if crush_check(login, crush):
                        crush_deltry(login, crush)
                        crush_addmutual(login, crush)
                        crush_addmutual(crush, login)
                        mokum_message(crush, "Your crush with @" + login + " is mutual!")
                        mokum_message(login, "You have a crush with @" + crush + ". Have a good time!")
                        guessorfail = "Yooohoo! You've mutual crush with  @" + crush + "!"
                    else:
                        if crush_add(login, crush):
                            crush_addtry(login, crush)
                            guessorfail = "Not for now, but we'll let " + crush + " know that someone has a crush on them."
                            mokum_message(crush, "Someone has a crush on you, check at https://movdut.0xd8.org/ :)")
                            crush_tries(login, 1)
                            crush_tries(crush, -1)
                        else:
                            guessorfail = "You already have a crush on this user!"
                            crush_addtry(login, crush)
            else:
                guessorfail = crush + " doesn't exist on Mokum (may be  deleted?) , try someone else!"

        tries = crush_tries(login)

        # if 'crushflash' in session:
        #     guessorfail = session['crushflash']
        #     print(session)
        #     del session['crushflash']

        if len(guessorfail) > 0:
            flash(guessorfail)
        return render_template("main.html", login=login, num=crush_num(login), guess=guessorfail, tries=tries,
                               mutual=crush_mutual(login), sent=crush_sent(login))
    else:
        return render_template('login.html')


@app.route('/crush/<name>/<action>')
def crushmenu(name, action):
    message = ""
    if 'login' in session:
        login = session['login']

        tries = crush_tries(login)
        name = name[1:]

        if action == "poke":

            try:
                attempt = int(r.get(login + "+poke"))
                message = "You have used your poke chance. Get back in a day or two"
            except:
                attempt = 1
                mokum_message(name, "Hi! Anonymous mokum user sends you a spare try on movdut!:).")
                crush_tries(name, -1)
                r.setex(login + "+poke", ttl * 2, 1)
                message = "You have poked @" + name + ". Good luck!"

        elif action == "revoke":
            try:
                attempt = int(r.get(login + "+revoke"))
                message = "You have already used your revoke right. Get back in a day or two"
            except:
                attempt = 1
                crush_deltry(login, name)
                crush_check(name, login)
                crush_tries(login, -1)
                r.setex(login + "+revoke", ttl * 2, 1)
                message = "You have revoked attempt and have got extra try"

        session['crushflash'] = message

        return redirect("/")
    else:
        return redirect("/signup")

        #     return redirect(url_for('.process',  login=login, num=crush_num(login), guess="", tries=tries,
        #                            mutual=crush_mutual(login), sent=crush_sent(login)))
        # else:
        #     return redirect(url_for('.signup'))


@app.route('/signup', methods=['POST'])
def signup():
    apikey = request.form['apikey']

    login = mokum_auth(apikey)
    if login:
        session['login'] = login

    return redirect('/')


@app.route('/logout')
def logout():
    if 'login' in session:
        del session['login']
    return redirect('/')


@app.route('/rulez')
def rulez():
    guessorfail = ""
    if 'login' in session:
        login = session['login']

        tries = crush_tries(login)

        if 'crushflash' in session:
            guessorfail = session['crushflash']
            # print(session)
            del session['crushflash']

        if len(guessorfail) > 0:
            flash(guessorfail)

        return render_template('rulez.html', login=login)
    else:
        return render_template('login.html')


if __name__ == '__main__':
    app.run()
