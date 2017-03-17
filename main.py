from flask import Flask
from flask import request, redirect, session, render_template
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
r = redis.StrictRedis()

with open("app_config.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)

app.secret_key = cfg['app']['secretkey']
postapikey = cfg['app']['postapikey']
ttl = cfg['users']['timeout']
ntries = cfg['users']['ntries']

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
        print (e)
        r.lpush(login + "+tries", encrypt(crush, login))
    return True


def crush_deltry(login, crush):
    try:
        for i in r.lrange(login + "+tries", 0, -1):
            if decrypt(i, login) == crush:
                r.lpop(login + "+tries", i)
                return True
    except:
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
                r.lpop(login + "+mutual", i)
                return True
    except:
        return False

    return False

def crush_ismutal(login,crush):
    try:
        for i in r.lrange(login + "+mutual", 0, -1):
            if decrypt(i, login) == crush:
                return True
    except:
        return False
    return False

def crush_mutual(login):
    mutualcrushes = "Your mutal crushes: "
    try:
        for i in r.lrange(login + "+mutual", 0, -1):
            mutualcrushes += "@" + decrypt(i, login) + ", "
        mutualcrushes += "."
    except:
        mutualcrushes = "No mutal cruses yet :("
    return mutualcrushes


def crush_sent(login):
    sentcrushes = "You have send crushes to: "
    try:
        for i in r.lrange(login + "+mutual", 0, -1):
            sentcrushes += "@" + decrypt(i, login) + ", "
        sentcrushes += "."
    except:
        sentcrushes = "You don't send crushes to anyone :("
    return sentcrushes


def crush_tries(login, incr=0):
    try:
        tries = int(r.get(login + "+count"))
    except:
        tries = ntries
        r.setex(login + "+count", ttl, tries)

    if incr != 0:
        tries -= incr
        if tries < 0:
            tries = 0
        r.setex(login + "+count", ttl, tries)

    return tries


@app.route('/')
def process():
    if 'login' in session:
        login = session['login']

        if crush_tries(login) > 0:
            tries = "You have " + str(crush_tries(login)) + " tries left."
        else:
            tries = "You have no tries left :(, try again in a couple of days"

        return render_template('main.html', login=login, num=crush_num(login), guess="", tries=tries,
                               mutual=crush_mutual(login), sent=crush_sent(login))
    else:
        return render_template('login.html')


@app.route('/guessortry', methods=['POST'])
def makeguess():
    guessorfail = ""

    if 'login' in session:
        login = session['login']
        crush = request.form['crush']
        crush = crush.strip()
        if len(crush) > 0:
            if (request.form['submit'] == 'Check!'):
                print("check")
                if (crush_stat(login, crush)):
                    guessorfail = "You have already sent your crush to @" + crush + " ."
                    crush_addtry(login, crush)
                elif crush_ismutual(login, crush):
                    guessorfail = "You already have a mutual crush with @" + crush + " , why are you checking? :)"
                else:
                    guessorfail = "We don't see any crushes to @" + crush + " ,  so do make a try!"

            elif mokum_check(crush):
                if crush_tries(login) > 0:
                    if crush_check(login, crush):
                        crush_deltry(login, crush)
                        crush_addmutual(login, crush)
                        mokum_message(crush, "Your crush on @" + login + " is mutal!")
                        mokum_message(login, "You have a crush with @" + crush + ". Well, good luck!")
                        guessorfail = "Yooohoo! You've guessed! It's " + crush + "!"
                    else:
                        if crush_add(login, crush):
                            crush_addtry(login, crush)
                            guessorfail = "Not this time, but we'll let " + crush + " know about your passion."
                            mokum_message(crush, "Someone has a crush for you, check at https://movdut.0xd8.org/ :)")
                            crush_tries(login, 1)
                            crush_tries(crush, -1)
                        else:
                            guessorfail = "You have already crushed this user!"
                            crush_addtry(login, crush)
            else:
                guessorfail = crush + " doesn't exist or deleted on Mokum, so may be another try?"

        if crush_tries(login) > 0:
            tries = "You have " + str(crush_tries(login)) + " tries left."
        else:
            tries = "You have no tries left :(, try again in a couple of days"

        return render_template("main.html", login=login, num=crush_num(login), guess=guessorfail, tries=tries,
                               mutual=crush_mutual(login), sent=crush_sent(login))
    else:
        return render_template('login.html')


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


if __name__ == '__main__':
    app.run()
