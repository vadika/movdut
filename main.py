from flask import Flask
from flask import request, redirect, session, render_template
import hashlib
import urllib
import json
import redis

app = Flask(__name__)
app.secret_key = "#d\xe9X\x00\xbe~Uq\x1fs\t\xb4\x99\xa3\x87\xe6.\xd1_\xebX\xae\x81'"
r = redis.StrictRedis()
ttl = 60*60*24*2
ntries = 5


#


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


def crash_num(login):
    try:
        return len(r.lrange(login, 0, -1))
    except:
        return 0


def crash_check(login, crash):
    for i in r.lrange(login, 0, -1):

        if str(calc_sha256(crash)) == i.decode("utf-8"):
            r.lrem(login, 0, i)
            return True
    return False


def crash_add(login, crash):
    r.lpush(crash, calc_sha256(login))
    return True


def crash_tries(login, incr=0):
    try:
        tries = int(r.get(login + "+count"))
    except:
        tries = ntries
        r.setex(login + "+count", ttl, tries)

    if incr > 0:
        if tries > 0:
            tries -= 1
            r.setex(login + "+count", ttl, tries)

    return tries


@app.route('/')
def process():
    if 'login' in session:
        login = session['login']
        return render_template('main.html', login=login, num=crash_num(login))
    else:
        return render_template('login.html')


@app.route('/guessortry', methods=['POST'])
def makeguess():
    guessorfail = ""

    if 'login' in session:
        login = session['login']
        crash = request.form['crash']
        crash = crash.strip()
        if len(crash) > 0:

            if crash_tries(login, 1) > 0:
                if crash_check(login, crash):
                    guessorfail = "Yooohoo! You've guessed! It's " + crash + "!"
                else:
                    guessorfail = "Not this time, but we'll let " + crash + " know about your passion."
                    crash_add(login, crash)

        if crash_tries(login) > 0:
            tries = "You have " + str(crash_tries(login)) + " tries left."
        else:
            tries = "You have no tries left :(, try again in a couple of days"

        return render_template("main.html", login=login, num=crash_num(login), guess=guessorfail, tries=tries)
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
