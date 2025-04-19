from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, emit
from flask_bcrypt import Bcrypt
from models import db, User, Message
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db.init_app(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    if 'username' in session:
        return redirect('/chat')
    return redirect('/login')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect('/login')
    return render_template('index.html', username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if User.query.filter_by(username=username).first():
            return "User already exists"
        db.session.add(User(username=username, password=password))
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            session['username'] = user.username
            return redirect('/chat')
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

@socketio.on('message')
def handle_message(msg):
    timestamp = datetime.now().strftime('%H:%M:%S')
    user = session.get('username', 'Anonymous')

    # Save message to database
    new_msg = Message(sender=user, content=msg, timestamp=timestamp)
    db.session.add(new_msg)
    db.session.commit()

    # Broadcast message
    formatted = f"[{timestamp}] {user}: {msg}"
    emit('message', formatted, broadcast=True)

@app.route('/messages')
def get_messages():
    messages = Message.query.order_by(Message.id).all()
    return {
        "messages": [f"[{m.timestamp}] {m.sender}: {m.content}" for m in messages]
    }

if __name__ == '__main__':
    socketio.run(app, debug=True)
