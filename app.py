from datetime import datetime
from flask import Flask, render_template, request, make_response, jsonify
import jwt, datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'dfc8af4c635a45d89aad84fcab049609'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = request.args.get('token')


        if not token:
            return jsonify({'message':"Token in missing"}, 403)
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            print(e)
            return jsonify({'message':"Token is invalid"}, 403)
        return f(*args, **kwargs)

    return decorated

@app.route('/unprotected')
def unprotected():
    return jsonify({'message':"Any one can view this unprotected view"})

@app.route('/protected')
@token_required
def protected():
    return jsonify({'message':"Only token varified user can view this protected view"})

@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password == "password":
        token = jwt.encode({'user' : auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.encode().decode('utf-8')})

    return make_response('Could Not Verify!', 401, {'WWW-Authenticate':'Basic realm="Login Required"'})



if __name__ == "__main__":
    app.run(debug=True,  port=8000)