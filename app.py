from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, send
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

# In-memory "DB"
users = {}

@app.route('/')
def home():
    if 'username' in session:
        return render_template('chat.html', username=session['username'])
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        users[username] = hashed
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        stored = users.get(username)
        if stored and bcrypt.checkpw(password, stored):
            session['username'] = username
            return redirect('/')
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@socketio.on('message')
def handle_message(msg):
    print(f"Message: {msg}")
    send(msg, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
