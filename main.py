from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
import os
import pandas as pd
import requests
from datetime import date
from datetime import datetime as dt
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), 'library.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
db.create_all()


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            print(e)
            return jsonify({'message': 'token is invalid'})
        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(data)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(name=auth.username).first()
    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/users', methods=['GET'])
def get_all_users():
    users = Users.query.all()

    result = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        result.append(user_data)

    return jsonify({'users': result})

parse_date = lambda fecha: str(date(int(fecha[6:]), int(fecha[4:5]), int(fecha[:2])))

def diario_oficial_de_la_federacion():
    fechaInicial = dt.now().strftime("01/%m/%Y")
    fechaFinal = dt.now().strftime("%d/%m/%Y")
    url = "https://www.banxico.org.mx/tipcamb/tipCamIHAction.do?fechaInicial={}&fechaFinal={}".format(fechaInicial, fechaFinal)
    df = pd.read_html(url, match="Fecha")[1]
    last_date = parse_date(df[0][1].split("  ")[-1])+"T{}Z".format(dt.timetz(dt.now()))
    last_price = df[1][1].split("  ")[-1]
    return {"last_date": last_date, "last_price": last_price}

def fixer_io():
    access_key = "e79077b6dc2f0b2c92a549f6a319e0ad"
    r = requests.get("http://data.fixer.io/api/latest?access_key={}".format(access_key))
    rates = r.json()["rates"]
    usd = rates["USD"]
    mxn = rates["MXN"]
    last_date = dt.now().strftime("%Y-%m-%d")+"T{}Z".format(dt.timetz(dt.now()))
    return {"last_price": "{:.4f}".format(mxn/usd), "last_date": last_date}

def Banxico():
    headers = {
              "Accept": "application/json",
              "Bmx-Token": "845a0f7583215fd411ce579d5a6fa960141e01856abb6398169c4d0128f6aeb4"
            }
    url = "https://www.banxico.org.mx/SieAPIRest/service/v1/series/SF60653/datos/oportuno"
    r = requests.get(url, headers=headers).json()
    data = r["bmx"]["series"][0]["datos"][0]
    last_price = float(data["dato"])
    last_date = parse_date(data["fecha"])+"T{}Z".format(dt.timetz(dt.now()))
    return {"last_price": last_price, "last_date": last_date}

@app.route('/exchange_rate', methods=['GET'])
@token_required
def exchange_rate(current_user):
    return {
            "rates":
                {
                    "Diario oficial de la federacion": {
                        "last_updated": diario_oficial_de_la_federacion()["last_date"],
                        "value": diario_oficial_de_la_federacion()["last_price"]
                    },
                    "Fixer": {
                        "last_updated": fixer_io()["last_date"],
                        "value": fixer_io()["last_price"]
                    },
                    "Banxico": {
                        "last_updated": Banxico()["last_date"],
                        "value": Banxico()["last_price"]
                    }
                }
            }

if  __name__ == '__main__':
     app.run(debug=True)