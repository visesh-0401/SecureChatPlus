from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO, send
import bcrypt
import os
import json

from utils.crypto_utils import (
    generate_rsa_keypair,
    encrypt_aes_key_with_rsa,
    aes_encrypt
)

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

# In-memory databases
users = {}               # username -> hashed password
session_keys = {}        # username -> AES key
chat_log = []            # stores encrypted messages

# RSA Keys for the server (2048-bit)
PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keypair()


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

        if username in users:
            return "User already exists"

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


# Assign AES key to user on WebSocket connect
@socketio.on('connect')
def on_connect():
    username = session.get('username')
    if username:
        from Crypto.Random import get_random_bytes
        aes_key = get_random_bytes(16)
        session_keys[username] = aes_key
        encrypted_key = encrypt_aes_key_with_rsa(PUBLIC_KEY, aes_key)
        print(f"[SecureChat+] AES key for {username} encrypted with RSA and ready for use.")
        # In production: send encrypted key to the client via a secure method


@socketio.on('message')
def handle_message(msg):
    sender = session.get('username')
    aes_key = session_keys.get(sender)

    if not aes_key:
        send("[Encryption error: No AES key assigned]", broadcast=False)
        return

    encrypted = aes_encrypt(aes_key, msg)
    chat_log.append({
        'sender': sender,
        'encrypted': encrypted
    })

    send(json.dumps({
        'sender': sender,
        'encrypted': encrypted
    }), broadcast=True)


if __name__ == '__main__':
    socketio.run(app, debug=True)
