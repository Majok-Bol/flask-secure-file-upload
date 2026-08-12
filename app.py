from flask import Flask,render_template,redirect,flash,url_for,make_response
from flask_wtf import FlaskForm,CSRFProtect
from wtforms import StringField,SubmitField,EmailField,PasswordField
from wtforms.validators import Email,EqualTo,Length,InputRequired
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
from flask_jwt_extended import(
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager,
    unset_jwt_cookies,
    set_access_cookies,
    set_refresh_cookies,
    create_refresh_token
)
from flask_bcrypt import Bcrypt

from datetime import timedelta
#load env variables
load_dotenv()
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']=os.getenv("DATABASE_URL")
# print("URL: ",url)
app.config['SECRET_KEY']=os.getenv("CSRF_SECRET_KEY")
#configure JWT SECRET KEY
app.config['JWT_SECRET_KEY']=os.getenv("JWT_SECRET_KEY")
#where to find token
#store in the cookie
app.config['JWT_TOKEN_LOCATION']=["cookies"]
#name for cookie that will store the access token
app.config['JWT_ACCESS_COOKIE_NAME']="access_token"
#sent over HTTPS,Production set it to true
app.config['JWT_COOKIE_SECURE']=False
#csrf protection for JWT
app.config['JWT_COOKIE_CSRF_PROTECT']=False #in production set it to True
#no JS access
app.config['JWT_COOKIE_HTTPONLY']=False #set it to True in production
#prevent cross origin requests
app.config['JWT_COOKIE_SAMESITE']='Lax' #set to Strict in production to only accept requests from same domain or subdomains
#token expiration for JWT
app.config['JWT_ACCESS_TOKEN_EXPIRES']=timedelta(minutes=15)
#refresh token to prevent redirecting to login again
app.config['JWT_REFRESH_TOKEN_EXPIRES']=timedelta(days=30)
#initialize app with database
db=SQLAlchemy(app)
#initialize flask_migrate
#to handle database schema changes automatically
migrate=Migrate()
migrate.init_app(app,db)
csrf=CSRFProtect()
csrf.init_app(app)
jwt=JWTManager()
jwt.init_app(app)
#initialize bcrypt
bcrypt=Bcrypt()
bcrypt.init_app(app)
#initialize csrf protect globally
csrf=CSRFProtect()
csrf.init_app(app)
@app.route("/",methods=["POST","GET"])
def home():
    return render_template("home.html")
@app.route("/register",methods=["POST","GET"])
def register():

    form=RegisterForm()

    if form.validate_on_submit():

        username=form.username.data

        email=form.email.data

        password=form.password.data

        username_exists=User.query.filter_by(username=username)

        email_exists=User.query.filter_by(email=email)

        if username_exists:
            print("Username not available.Please choose another username")

        if email_exists:
            print("Email address not available.Please choose another email.")
        #hash password
        password_hashed=bcrypt.generate_password_hash(password).decode("utf-8")

        user=User(username=username,email=email,password=password_hashed)

        db.session.add(user)

        db.session.commit()
        print("Account created successfully")

        return redirect(url_for('login'))
    
    return render_template("register.html",form=form)

@app.route("/login",methods=["POST","GET"])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        #check username
        username=form.username.data
        password=form.password.data
        #check username
        user=User.query.filter_by(username=username).first()
        print("Username found: ",user)
        if not user or not bcrypt.check_password_hash(user.password,password):
            print("Invalid username or password")
            return redirect(url_for('login'))
        #create access token for user
        access_token=create_access_token(identity=str(user.id))
        print("Access token generated: ",access_token)
        #create refresh token 
        refresh_token=create_refresh_token(identity=str(user.id))
        print("Refresh token generated: ",refresh_token)
        # return redirect(url_for('dashboard'))
        response=make_response(redirect(url_for("dashboard")))
        #set cookies
        #set_access_cookies
        set_access_cookies(response,access_token)
        #set refresh cookies
        set_refresh_cookies(response,refresh_token)
        return response
    return render_template('login.html',form=form)
#refresh route
@app.route("/refresh",methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    #get user id
    user_id=get_jwt_identity()
    print("User id: ",user_id)
    access_token=create_access_token(identity=user_id)
    print("Refresh token: ",access_token)
    response=make_response(redirect(url_for("home")))
    set_access_cookies(response,access_token)
    print("Refresh cookies set: ",set_refresh_cookies)
    return response   
@app.route("/dashboard",methods=["POST","GET"])
@jwt_required()
def dashboard():
    #get user id
    user_id=get_jwt_identity()
    user=db.session.get(User,int(user_id))
    print("User id: ",user)
    if not user:
        return redirect(url_for("login"))
    return render_template("dashboard.html",user=user)
@app.route("/logout")
def logout():
    #redirect to login page after logout
    response=make_response(redirect(url_for("login")))
    unset_jwt_cookies(response)
    print("You have been logged out")
    return response
    # return render_template("logout.html")
@app.route("/uploads")
def uploads():
    return render_template("uploads.html")

#customize JWT error messages
#invalid token provided in the request
@jwt.invalid_token_loader
def invalid_token_loader(reason):
    print("Reason: ",reason)
    return redirect(url_for("login"))
#no token provided in the request
@jwt.unauthorized_loader
def missing_token_callback(reason):
    print("Reason: ",reason)
    return redirect(url_for("login"))
#expired token provided
@jwt.expired_token_loader
def expired_token_loader(jwt_header,jwt_payload):
    print("JWT Header: ",jwt_header)
    print("JWT Payload: ",jwt_payload)
    return redirect(url_for("login"))
#
#register form
class RegisterForm(FlaskForm):
    username=StringField("Username",validators=[Length(min=4)])
    email=EmailField("Email address",validators=[InputRequired(),Email()])
    password=PasswordField("Password",validators=[InputRequired(),Length(min=8)])
    confirm_password=PasswordField("Confirm password",validators=[EqualTo("password",message="Passwords must match")])
    submit=SubmitField("Sign up")

#login form
class LoginForm(FlaskForm):
    username=StringField("Username")
    password=PasswordField("Password")
    submit=SubmitField("Login")
#database model
class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(10))
    email=db.Column(db.String(100))
    password=db.Column(db.String(255))
    

if __name__=="__main__":
    app.run(debug=True)