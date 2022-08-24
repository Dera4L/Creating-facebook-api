import os, secrets, cloudinary as Cloud
from flask import (
    Flask,
    jsonify,
    make_response,
    request,
    json,
    render_template,
    Blueprint,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    decode_token,
    JWTManager,
    jwt_required,
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from PIL import Image


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "gvdvrfegheuogh549586dshbfjfer"
db = SQLAlchemy(app)  # declaring database contexts
jwt = JWTManager(app)
cor = CORS(app)
# login_manager = LoginManager(app)


Cloud.config(
    cloud_name="dumqm2s5v",
    api_key="461698878482255",
    api_secret_key="ew8zWQW64vWED9rkV5VWhEnJXaI",
)


class User(db.Model):
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(400), nullable=False)
    username = db.Column(db.String(400), nullable=False)


class Post(db.Model):
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    title = db.Column(db.String)
    imageurl = db.Column(db.String(300))
    # likes = db.Column(db.Integer)
    # comment = db.Column(db.String(1000))


class PostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    post_id = db.Column(db.Integer)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_text = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)


@app.post("/comment")
def comment():
    comment_text = request.json["comment"]
    post_id = request.json["post_id"]
    post = Post.query.filter_by(id=post_id).first()
    if not post:
        return {"msg": "post not found"}
    access_token = request.headers.get("Authorization")
    if not access_token:
        return make_response(
            jsonify({"message": "please login to perform this action"})
        )

    token = access_token.split(" ")
    decoded_token = decode_token(token[1])
    user = decoded_token["sub"]
    commentbox = Comment(user_id=user["id"], comment_text=comment_text)
    db.session.add(commentbox)
    db.session.commit()

    return make_response(jsonify({"msg": "Successfully commented on this post"}))


@app.post("/like")
def like_post():
    access_token = request.headers.get("Authorization")
    if not access_token:
        return make_response(
            jsonify({"message": "please login to perform this action"})
        )

    token = access_token.split(" ")
    decoded_token = decode_token(token[1])
    post_id = request.json["post_id"]
    post = Post.query.filter_by(id=post_id).first()
    if not post:
        return {"msg": "post not found"}
    user = decoded_token["sub"]
    like = PostLike(user_id=user["id"], post_id=post_id)
    db.session.add(like)
    db.session.commit()
    return make_response(jsonify("DONE"))


@app.route("/login", methods=["GET", "POST"])
def handle_login():
    data = request.json
    email = data["email"]
    passwd = data["password"]

    user = User.query.filter_by(email=email).first()

    if not user:
        return make_response(
            jsonify(
                {
                    "msg": "This email is not valid, click on signup to create a new account"
                }
            )
        )

    if check_password_hash(user.password, passwd):
        access_token = create_access_token(
            {"id": user.id, "email": user.email, "username": user.username}
        )
        return make_response(
            jsonify({"msg": "Login successful", "access token": access_token})
        )
    else:
        return make_response(
            jsonify("Incorrect password, Please check your password and try again")
        )


@app.route("/")
def hello():
    return "Hello"


def saveImageToCloud(image):

    random_hex = secrets.token_hex(8)
    _, ext = os.path.splitext(image.filename)
    image_fn = random_hex + ext

    size = (125, 125)
    i = Image.open(image)
    i.thumbnail(size)
    image_url = Cloud.CloudinaryImage(image_fn)

    return image_url.url


# @app.route('/post', methods=['GET','POST'])
@app.post("/post")
def make_post():

    imageurl = request.files["imageurl"]
    title = request.form["title"]

    image_path = saveImageToCloud(imageurl)
    print(image_path)

    post = Post(imageurl=image_path, title=title)

    db.session.add(post)
    db.session.commit()
    return "Post made succesfully"


@app.get("/getallposts")
def get_all_posts():
    posts = Post.query.filter().all()
    content = []

    for post in posts:
        output = {
            "id": post.id,
            "title": post.title,
            "imageurl": post.imageurl,
            "likes": post.likes,
        }
        content.append(output)
    return make_response(jsonify({"These are all the posts": content}))


@app.delete("/delete/<id>")
def delete_posts(id):
    post = Post.query.get(id)

    if post is None:
        return {"error": "Post not found"}
    db.session.delete(post)
    db.session.commit()
    return {"msg": "deleted"}


@app.post("/signup")
def create_user():
    file = request.json
    password = request.json["password"]
    email = request.json["email"]
    username = request.json["username"]
    hash_pw = generate_password_hash(password)

    check = User.query.filter_by(email=email).first()
    if check:
        return {"msg": "email already in use"}

    check2 = User.query.filter_by(username=username).first()
    if check2:
        return {"msg": "username already in use"}

    user = User(
        email=request.json["email"], password=hash_pw, username=request.json["username"]
    )

    db.session.add(user)
    db.session.commit()
    return make_response(
        jsonify(
            {
                "Message": "user created successfull",
                "UserData": {
                    "email": user.email,
                    # "password": user.password,
                    "username": user.username,
                    "Password": "to reset your password,click on reset".title(),
                },
            }
        )
    )


@app.get("/getmails")
def get_all_emails():
    user = User.query.filter().all()
    content = []

    for users in user:
        output = {"email": users.email}
        content.append(output)
    return make_response(jsonify({"All Emails": content}))


@app.get("/search")
def get_all_users():
    users = User.query.filter().all()
    content = []

    for user in users:
        output = {
            "id": user.id,
            "username": user.username,
            "password": user.password,
            "email": user.email,
        }
        content.append(output)
    return make_response(jsonify(content))


if __name__ == "__main__":
    app.run(debug=True)
