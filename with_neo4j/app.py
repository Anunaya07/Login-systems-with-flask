from distutils.log import debug
from flask import Flask, session, render_template, request, redirect, g, url_for
from flask_bcrypt import Bcrypt
import os
from neo4j import GraphDatabase
import datetime


app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt=Bcrypt(app)

uri = "neo4j://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "random"))

def check_username_existence(tx, username):
    username_list= []
    result = tx.run("match (user:user) where user.name= $name return user.name as username", name=username)
    for record in result:
        username_list.append(record["username"])
        if len(username_list) > 0:
            return False
    return True

def create_account(tx, username, password):
    dateTimeNow = datetime.datetime.today().strftime("%d-%m-%Y %I:%M %p")
    tx.run("CREATE (:user {name: $user})-[:pswd_in_use {datetime : $datetime}]->(:pswd {name: $password})",
           user=username, password=password,datetime = dateTimeNow)
    #CREATE (:user {name: $user})-[:pswd_in_use]->(:pswd {name: $password})

def user_authentication(tx, username, password):
    username_list= []
    result = tx.run('''match (user:user) - [:pswd_in_use] -> (password:pswd) 
    where user.name = $name
    return password.name as password''', name=username, password=password)
    # match (user:user) - [:pswd_in_use] -> (password:pswd) where user.name = $name and password.name = $password 
    # return user.name as username, password.name as password
    for record in result:
        if bcrypt.check_password_hash(record["password"], password):
             return True
        else:
            return False
    return False





@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        session.pop('user', None)
        username = request.form['username']
        password = request.form['password']
        with driver.session() as driver_session:
               auth_check = driver_session.read_transaction(user_authentication, username, password)
               if auth_check:
                 print("Logged in successfully")
                 session['user'] = username
                 return redirect(url_for('dashboard'))
               else:
                   print("Try again :(")
        driver.close()
    
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if g.user:
        return render_template('dashboard.html', user=session['user'])
    return redirect(url_for('index'))

@app.before_request
def before_request():
    g.user =None
    if 'user' in session:
        g.user = session['user']

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode("UTF-8")
        with driver.session() as driver_session:
               flag_check_username = driver_session.read_transaction(check_username_existence, username)
               if flag_check_username:
                      driver_session.write_transaction(create_account, username, password)
                      return redirect(url_for('index'))
               else:
                         print("Sorry username is already taken")
                         driver.close()
                         return redirect(url_for('sign_up'))
        
    
    return render_template('sign_up.html')



if __name__=='__main__':
    app.run(debug=True, port=5000)