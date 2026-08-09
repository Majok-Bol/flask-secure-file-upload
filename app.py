from flask import Flask,render_template,redirect,flash,url_for
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
#load env variables
load_dotenv()
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']=os.getenv("DATABASE_URL")
# print("URL: ",url)
app.config['SECRET_KEY']=os.getenv("CSRF_SECRET_KEY")
# print("sky: ",sky)
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

        user=User(username=username,email=email,password=password)

        db.session.add(user)

        db.session.commit()

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
        username_exists=User.query.filter_by(username=username)
        if not username_exists:
            print("Invalid username or password")
            return redirect(url_for('login'))
        return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

        
@app.route("/dashboard",methods=["POST","GET"])
def dashboard():
    return render_template("dashboard.html")
@app.route("/logout")
def logout():
    return render_template("logout.html")
@app.route("/uploads")
def uploads():
    return render_template("uploads.html")


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