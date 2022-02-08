import datetime
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid, jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = '725aed1d383e41f0ab788e3f50356666'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


def return_json(users):
    json_users = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['id'] = user.id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        json_users.append(user_data)
    
    return json_users


@app.route('/user', methods=['GET'])
def get_all_user():

    users = User.query.all()

    json_users = return_json(users)

    return jsonify({"users":json_users})

@app.route('/user/<user_id>', methods=['GET'])
def get_one_user(user_id):

    user = User.query.filter_by(id=user_id).first()
    li = []
    li.append(user)
    json_user = return_json(li)

    return jsonify({"user":json_user})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    hash_password = generate_password_hash(data['password'])

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hash_password, admin=False)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message":"New User Created"})
    
@app.route('/user/<user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.admin = True
        db.session.commit()
        return jsonify({"Msg":"User promoted to Admin"})
    else:
        return jsonify({"msg":"User not found!"})

@app.route('/user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"Msg":"User has been deleted"})
    else:
        return jsonify({"msg":"User not found!"})



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message':"Token in missing"}, 403)

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id'])

             
        except Exception as e:
            print(e)
            return jsonify({'message':"Token is invalid"}, 403)
        return f(*args, **kwargs)

    return decorated

@app.route('/login')
@token_required
def login():
    auth = request.authorization
    if auth and auth.username and auth.password:
        user = User.query.filter_by(name = auth.username).first()
        if not user:
            return make_response('Could Not Verify!', 401, {'WWW-Authenticate':'Basic realm="Login Required"'})
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id':user.public_id, 'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.encode().decode('utf-8')})
    
    else:
        return make_response('Could Not Verify!', 401, {'WWW-Authenticate':'Basic realm="Login Required"'})



if __name__ == "__main__":
    app.run(debug=True, port = 8001)