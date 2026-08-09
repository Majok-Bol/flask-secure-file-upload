from flask import Flask,render_template
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,EmailField,PasswordField
from wtforms.validators import Email,EqualTo,Length,InputRequired
from flask_sqlalchemy import SQLAlchemy
app=Flask(__name__)
#initialize app with database
db=SQLAlchemy(app)
@app.route("/",methods=["POST","GET"])
def home():
    return render_template("home.html")
@app.route("/register",methods=["POST","GET"])
def register():
    return render_template("register.html")
@app.route("/login")
def login():
    return render_template("login.html")
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
    username=StringField("Username",Length(min=4))
    email=EmailField("Email address",validators=[InputRequired(),Email()])
    password=PasswordField("Password",validators=[InputRequired(),Length(min=8)])
    confirm_password=PasswordField("Confirm password",EqualTo("password",message="Passwords must match"))
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