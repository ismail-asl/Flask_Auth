import datetime
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid, jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_migrate import Migrate

app = Flask(__name__)

app.config['SECRET_KEY'] = ''
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(400))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    updated_on = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())



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
            current_user = User.query.filter_by(public_id=data['public_id']).first()
             
        except Exception as e:
            print(e)
            return jsonify({'message':"Token is invalid"}, 403)

        return f(current_user, *args, **kwargs)

    return decorated



def return_json_user(users):
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


def return_json_posts(posts):
    json_posts = []
    for post in posts:
        post_data = {}
        post_data['user_id'] = post.user_id
        post_data['id'] = post.id
        post_data['title'] = post.title
        post_data['description'] = post.description
        post_data['created_on'] = post.created_on
        post_data['updated_on'] = post.updated_on
        json_posts.append(post_data)
    
    return json_posts

@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):

    if not current_user.admin:
        return jsonify({'msg':"Only admin can view all the users"})

    users = User.query.all()

    json_users = return_json_user(users)

    return jsonify({"users":json_users})

@app.route('/user/<user_id>', methods=['GET'])
@token_required
def get_one_user(current_user, user_id):

    if not current_user.admin:
        return jsonify({'msg':"Only admin can view all the users"})

    user = User.query.filter_by(id=user_id).first()
    li = []
    li.append(user)
    json_user = return_json_user(li)

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
@token_required
def update_user(current_user, user_id):

    # if not current_user.admin:
    #     return jsonify({'msg':"Only admin can view all the users"})

    user = User.query.filter_by(id=user_id).first()
    if user:
        user.admin = True
        db.session.commit()
        return jsonify({"Msg":"User promoted to Admin"})
    else:
        return jsonify({"msg":"User not found!"})

@app.route('/user/<user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):

    if not current_user.admin:
        return jsonify({'msg':"Only admin can view all the users"})

    user = User.query.filter_by(id=user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"Msg":"User has been deleted"})
    else:
        return jsonify({"msg":"User not found!"})

@app.route('/login')
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



@app.route('/post', methods=['POST'])
@token_required
def create_post(current_user):
    data = request.get_json()

    post = Post(user_id=current_user.id, title=data['title'], description=data['description'])

    db.session.add(post)
    db.session.commit()

    return jsonify({"msg":"Post created"})


@app.route('/post', methods=['GET'])
@token_required
def get_all_post(current_user):

    posts = Post.query.filter_by(user_id=current_user.id).all()

    json_posts = return_json_posts(posts)

    return jsonify({"your posts":json_posts})


@app.route('/post/<post_id>', methods=['GET'])
@token_required
def get_one_post(current_user, post_id):

    post = Post.query.filter_by(id=post_id, user_id= current_user.id).first()
    
    if post is None:
        return jsonify({"msg":"No such post found"})

    li = []
    li.append(post)
    json_posts = return_json_posts(li)

    return jsonify({"users":json_posts})


@app.route('/post/<post_id>', methods=['PATCH'])
@token_required
def update_post(current_user, post_id):

    data = request.get_json()
    post = Post.query.filter_by(id=post_id, user_id= current_user.id).first()

    if post:

        if data['title']:
            post.title = data['title']

        if data['description']:
            post.description = data['description']
        
        db.session.commit()

        return jsonify({"Msg":"Post has been updated!!"})
    else:
        return jsonify({"msg":"No such post found!"})



@app.route('/post/<post_id>', methods=['DELETE'])
@token_required
def delete_post(current_user,post_id):

    post = Post.query.filter_by(id=post_id, user_id= current_user.id).first()
    if post is None:
        return jsonify({"msg":"No such post found"})

    db.session.delete(post)
    db.session.commit()
    return jsonify({"msg":"post has been deleted"})


if __name__ == "__main__":
    app.run(debug=True, port = 8001)