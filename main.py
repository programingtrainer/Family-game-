import os
import random
import threading
import unicodedata
import hmac
import json
import secrets
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest, urlopen
from flask import Flask, abort, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, delete, select
from datetime import datetime, timedelta
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_from_directory

ARABIC_LETTERS = ['أ', 'ب', 'ت', 'ث', 'ج', 'ح', 'خ', 'د', 'ذ', 'ر', 'ز', 'س', 'ش', 'ص', 'ض', 'ط', 'ظ', 'ع', 'غ', 'ف', 'ق', 'ك', 'ل', 'م', 'ن', 'ه', 'و', 'ي']

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET') or os.urandom(32)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///familygame_vFinal.db'
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_REFRESH_EACH_REQUEST=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=bool(
        os.environ.get('REPLIT_DEV_DOMAIN')
        or os.environ.get('REPLIT_DOMAINS')
        or os.environ.get('REPLIT_DEPLOYMENT')
    ),
    SESSION_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_DURATION=timedelta(days=7),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=bool(
        os.environ.get('REPLIT_DEV_DOMAIN')
        or os.environ.get('REPLIT_DOMAINS')
        or os.environ.get('REPLIT_DEPLOYMENT')
    ),
    REMEMBER_COOKIE_SAMESITE='Lax',
)

def _socket_allowed_origins():
    origins = {'http://localhost:5000', 'http://127.0.0.1:5000'}
    domains = set()
    for variable in ('REPLIT_DEV_DOMAIN', 'REPLIT_DOMAINS'):
        for value in os.environ.get(variable, '').split(','):
            domain = value.strip().lower()
            domain = domain.removeprefix('https://').removeprefix('http://')
            domain = domain.split('/', 1)[0].split(':', 1)[0].rstrip('.')
            if domain:
                domains.add(domain)
    for domain in domains:
        origins.add(f'https://{domain}')
        origins.add(f'https://{domain}:8080')
    return sorted(origins)

socketio = SocketIO(app, cors_allowed_origins=_socket_allowed_origins())

# Socket.IO state is held in memory for this single-process SQLite application.
lobby_rooms = {}
active_user_sids = {}
socket_user_ids = {}
state_lock = threading.RLock()

db = SQLAlchemy(app)

# 1. إعداد LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # اسم الـ route بتاع صفحة الدخول عندك

def get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


@app.context_processor
def inject_security_template_values():
    return {
        'csrf_token': get_csrf_token,
        'turnstile_site_key': os.environ.get('TURNSTILE_SITE_KEY', '')
    }


@app.before_request
def protect_unsafe_requests():
    if request.path.startswith('/socket.io/'):
        return
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return

    supplied_token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    expected_token = session.get('_csrf_token')
    if (
        not isinstance(supplied_token, str)
        or not isinstance(expected_token, str)
        or not hmac.compare_digest(supplied_token, expected_token)
    ):
        abort(400, description='Invalid or missing CSRF token')


@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    if request.endpoint in {'login', 'signup'}:
        response.headers['Cache-Control'] = 'no-store'
    if (
        request.is_secure
        or os.environ.get('REPLIT_DEV_DOMAIN')
        or os.environ.get('REPLIT_DOMAINS')
        or os.environ.get('REPLIT_DEPLOYMENT')
    ):
        response.headers.setdefault(
            'Strict-Transport-Security',
            'max-age=31536000; includeSubDomains'
        )
    return response


def verify_turnstile(token, expected_action):
    secret_key = os.environ.get('TURNSTILE_SECRET_KEY')
    if not secret_key or not os.environ.get('TURNSTILE_SITE_KEY'):
        return False
    if not isinstance(token, str) or not token or len(token) > 2048:
        return False

    payload = urlencode({
        'secret': secret_key,
        'response': token,
        'idempotency_key': str(uuid.uuid4())
    }).encode('ascii')
    api_request = UrlRequest(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        data=payload,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST'
    )
    try:
        with urlopen(api_request, timeout=8) as response:
            result = json.loads(response.read(16384))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        app.logger.warning('Cloudflare Turnstile verification was unavailable')
        return False

    return (
        isinstance(result, dict)
        and result.get('success') is True
        and result.get('action') == expected_action
    )


def start_authenticated_session(user):
    session.clear()
    login_user(user, remember=True, duration=timedelta(days=7))
    session.permanent = True
    session['user_id'] = user.id
    session['username'] = user.username
    session['_csrf_token'] = secrets.token_urlsafe(32)


# --- تعريف الجداول ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    points = db.Column(db.Integer, default=0)
    is_blocked = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    bio = db.Column(db.String(200), default="لاعب جديد في FamilyGame")
    avatar = db.Column(db.String(200), default="default.png")
    is_online_status = db.Column(db.Boolean, default=False)

    # التعديل هنا: استخدمنا back_populates بدل backref لمنع التداخل
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender', cascade='all, delete-orphan')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', back_populates='receiver', cascade='all, delete-orphan')

    @property
    def level(self):
        return (self.points // 500) + 1

    @property
    def progress_to_next_level(self):
        return (self.points % 500) / 5

    @property
    def is_online(self):
        return bool(self.is_online_status)
    
class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # المرسل
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # المستقبل
    status = db.Column(db.String(20), default='pending') # pending أو accepted

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # صاحب الإشعار
    message = db.Column(db.String(200), nullable=False)
    is_read = db.Column(db.Boolean, default=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    # التعديل هنا: نربطها بـ back_populates لتتناسب مع كلاس User
    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], back_populates='received_messages')

with app.app_context():
    db.create_all()
    User.query.update({User.is_online_status: False})
    db.session.commit()

# --- Routes الأصدقاء ---

@app.route('/friends', methods=['GET', 'POST'])
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    search_results = []
    if request.method == 'POST':
        query = request.form.get('search_query')
        stmt = select(User).where(User.username.like(f'%{query}%'), User.id != user.id)
        search_results = db.session.execute(stmt).scalars().all()

    friend_conns = Friend.query.filter_by(user_id=user.id, status='accepted').all()
    my_friends = [db.session.get(User, f.friend_id) for f in friend_conns if db.session.get(User, f.friend_id)]

    return render_template('friends.html', results=search_results, my_friends=my_friends, user=user)

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
def add_friend(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    if sender_id == friend_id:
        flash("لا يمكنك إرسال طلب صداقة لنفسك")
        return redirect(url_for('friends'))
    target = db.session.get(User, friend_id)
    if not target:
        flash("هذا المستخدم غير موجود")
        return redirect(url_for('friends'))

    existing = Friend.query.filter(
        ((Friend.user_id == sender_id) & (Friend.friend_id == friend_id)) |
        ((Friend.user_id == friend_id) & (Friend.friend_id == sender_id))
    ).first()
    if existing:
        flash("طلب الصداقة موجود بالفعل أو أنكما صديقان")
        return redirect(url_for('friends'))

    new_friend = Friend(user_id=sender_id, friend_id=friend_id, status='pending')
    db.session.add(new_friend)
    db.session.commit()
    sender = db.session.get(User, sender_id)
    socketio.emit('friend_request', {
        'request_id': new_friend.id,
        'from_username': sender.username
    }, room=f"user_{friend_id}")
    return redirect(url_for('friends'))

# --- Routes الدخول والتسجيل ---

@app.route('/')
def welcome():
    if current_user.is_authenticated:
        return render_template('welcome.html', returning_user=current_user)
    return render_template('welcome.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if not verify_turnstile(request.form.get('cf-turnstile-response'), 'signup'):
            return render_template(
                'signup.html',
                error='تعذر التحقق من الحماية. حدّث التحدي وحاول مرة أخرى.'
            ), 400

        user_name = (request.form.get('username') or '').strip()
        pass_word = request.form.get('password') or ''
        confirm_pwd = request.form.get('confirm_password') or ''

        if not 3 <= len(user_name) <= 80:
            return render_template('signup.html', error='اسم المستخدم لازم يكون بين 3 و80 حرفاً'), 400
        if not 12 <= len(pass_word) <= 128:
            return render_template('signup.html', error='كلمة المرور لازم تكون بين 12 و128 حرفاً'), 400
        if pass_word != confirm_pwd:
            return render_template('signup.html', error='كلمتا المرور غير متطابقتين'), 400

        existing_user = User.query.filter_by(username=user_name).first()
        if existing_user:
            return render_template('signup.html', error='اسم المستخدم غير متاح'), 409

        hashed_password = generate_password_hash(pass_word)
        new_user = User(username=user_name, password=hashed_password)
        db.session.add(new_user)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception('Account creation failed')
            return render_template('signup.html', error='تعذر إنشاء الحساب الآن. حاول مرة أخرى.'), 500

        start_authenticated_session(new_user)
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if not verify_turnstile(request.form.get('cf-turnstile-response'), 'login'):
            return render_template(
                'login.html',
                error='تعذر التحقق من الحماية. حدّث التحدي وحاول مرة أخرى.'
            ), 400

        user_name = (request.form.get('username') or '').strip()
        pass_word = request.form.get('password') or ''
        user = User.query.filter_by(username=user_name).first()

        password_valid = False
        if user and pass_word:
            if user.password.startswith(('pbkdf2:', 'scrypt:', 'sha256$')):
                try:
                    password_valid = check_password_hash(user.password, pass_word)
                except (TypeError, ValueError):
                    password_valid = False
            elif hmac.compare_digest(user.password, pass_word):
                password_valid = True
                user.password = generate_password_hash(pass_word)
                db.session.commit()

        if password_valid and user and not user.is_blocked:
            start_authenticated_session(user)
            return redirect(url_for('dashboard'))

        return render_template('login.html', error='اسم المستخدم أو كلمة المرور غير صحيحة'), 401

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])

    # جلب الطلبات المعلقة
    requests = Friend.query.filter_by(friend_id=user.id, status='pending').all()
    pending_requests = [{'id': r.id, 'username': db.session.get(User, r.user_id).username} for r in requests]

    # جلب الإشعارات غير المقروءة
    notifications = Notification.query.filter_by(user_id=user.id, is_read=False).all()

    # تحويل الإشعارات لـ "مقروءة" فوراً عشان الجرس ينطفي المرة الجاية
    for note in notifications:
        note.is_read = True
    db.session.commit()

    return render_template('dashboard.html', user=user, requests=pending_requests, notifications=notifications)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('welcome'))

# --- Routes الإعدادات ---

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    return render_template('settings.html', user=user)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    new_pwd = request.form.get('new_password')
    confirm_pwd = request.form.get('confirm_password')

    if new_pwd != confirm_pwd:
        return render_template('settings.html', error="غير متطابقة", user=user)

    user.password = generate_password_hash(new_pwd)
    db.session.commit()
    return render_template('settings.html', success="تم التغيير ✅", user=user)

# --- لوحة التحكم (gatapro901) ---

@app.route('/admin_panel')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if user.username != 'gatapro901':
        return "Unauthorized", 403

    users_list = User.query.filter(User.username != 'gatapro901').all()
    users_count = User.query.filter(User.username != 'gatapro901').count()
    return render_template('admin.html', users=users_list, total_count=users_count, user=user)

@app.route('/toggle_block/<int:user_id>', methods=['POST'])
def toggle_block(user_id):
    admin = db.session.get(User, session.get('user_id'))
    if not admin or admin.username != 'gatapro901':
        return "Unauthorized", 403
    target = db.session.get(User, user_id)
    if target:
        target.is_blocked = not target.is_blocked
        db.session.commit()
    return redirect(url_for('admin_panel'))

# دالة حذف المستخدم من لوحة التحكم (للأدمن)
@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    admin = db.session.get(User, session.get('user_id'))
    if not admin or admin.username != 'gatapro901':
        return 'Unauthorized', 403
    if user_id == admin.id:
        flash('لا يمكن حذف حساب الإدارة من هذه الصفحة')
        return redirect(url_for('admin_panel'))

    user = User.query.get_or_404(user_id)

    try:
        Message.query.filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).delete()
        Friend.query.filter((Friend.user_id == user_id) | (Friend.friend_id == user_id)).delete()
        Notification.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('admin_panel'))

    except Exception:
        db.session.rollback()
        app.logger.exception('Admin user deletion failed')
        flash('تعذر حذف المستخدم الآن')
        return redirect(url_for('admin_panel'))

# دالة حذف الحساب (للمستخدم نفسه من الإعدادات)
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = current_user.id
    user = User.query.get(user_id)

    try:
        Message.query.filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).delete()
        Friend.query.filter((Friend.user_id == user_id) | (Friend.friend_id == user_id)).delete()
        Notification.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()

        session.clear()
        logout_user()
        return redirect(url_for('welcome'))
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Account deletion failed')
        return 'تعذر حذف الحساب الآن', 500

@app.route('/leaderboard')
def leaderboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # جلب أفضل 10 لاعبين مع استبعاد الأدمن (gatapro901)
    top_players = User.query.filter(User.username != 'gatapro901')\
                            .order_by(User.points.desc())\
                            .limit(10).all()

    current_user = db.session.get(User, session['user_id'])

    return render_template('leaderboard.html', players=top_players, user=current_user)

@app.route('/accept_friend/<int:request_id>', methods=['POST'])
def accept_friend(request_id):
    if 'user_id' not in session: return redirect(url_for('login'))

    req = db.session.get(Friend, request_id)
    if req and req.friend_id == session['user_id'] and req.status == 'pending':
        req.status = 'accepted'

        reverse_exists = Friend.query.filter_by(
            user_id=session['user_id'], friend_id=req.user_id, status='accepted'
        ).first()
        if not reverse_exists:
            db.session.add(Friend(
                user_id=session['user_id'],
                friend_id=req.user_id,
                status='accepted'
            ))

        new_note = Notification(
            user_id=req.user_id,
            message=f"وافق {session.get('username', 'صديقك')} على طلب صداقتك"
        )
        db.session.add(new_note)
        db.session.commit()
        socketio.emit('friend_accepted', {
            'username': session.get('username', 'صديقك')
        }, room=f"user_{req.user_id}")

    return redirect(url_for('dashboard'))

@app.route('/reject_friend/<int:request_id>', methods=['POST'])
def reject_friend(request_id):
    if 'user_id' not in session: return redirect(url_for('login'))

    req = db.session.get(Friend, request_id)
    if req and req.friend_id == session['user_id']:
        db.session.delete(req)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/unfriend/<int:friend_id>', methods=['POST'])
def unfriend(friend_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    u_id = session['user_id']
    # حذف الصداقة من الطرفين
    Friend.query.filter(
        ((Friend.user_id == u_id) & (Friend.friend_id == friend_id)) |
        ((Friend.user_id == friend_id) & (Friend.friend_id == u_id))
    ).delete()
    db.session.commit()
    return redirect(url_for('friends'))

@app.route('/profile/<int:user_id>')
def profile(user_id):
    if 'user_id' not in session: return redirect(url_for('login'))

    target_user = db.session.get(User, user_id)
    if not target_user: return "المستخدم غير موجود", 404

    # التأكد من أنهما أصدقاء لرؤية البيانات الحساسة
    is_friend = Friend.query.filter_by(user_id=session['user_id'], friend_id=user_id, status='accepted').first()

    return render_template('profile.html', target=target_user, is_friend=is_friend)

@app.before_request
def update_last_seen():
    if current_user.is_authenticated and request.endpoint != 'static':
        now = datetime.utcnow()
        if not current_user.last_seen or (now - current_user.last_seen).total_seconds() >= 30:
            current_user.last_seen = now
            db.session.commit()

@app.context_processor
def inject_unread_count():
    if 'user_id' in session:
        count = Message.query.filter_by(receiver_id=session['user_id'], is_read=False).count()
        return dict(unread_messages_count=count)
    return dict(unread_messages_count=0)

@app.route('/inbox')
def inbox():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    # هنجيب كل الرسائل اللي اليوزر طرف فيها
    messages = Message.query.filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).order_by(Message.timestamp.desc()).all()

    conversations = []
    contacted_ids = set()

    for msg in messages:
        friend_id = msg.receiver_id if msg.sender_id == user_id else msg.sender_id
        if friend_id not in contacted_ids:
            friend = db.session.get(User, friend_id)
            unread_count = Message.query.filter_by(sender_id=friend_id, receiver_id=user_id, is_read=False).count()
            conversations.append({
                'friend': friend,
                'last_message': msg.content,
                'time': msg.timestamp.strftime('%I:%M %p'),
                'unread_count': unread_count
            })
            contacted_ids.add(friend_id)

    return render_template('inbox.html', conversations=conversations)

@app.route('/chat/<int:friend_id>')
def chat(friend_id):
    if 'user_id' not in session: return redirect('/login')

    friend = db.session.get(User, friend_id)
    # جلب الرسايل بين الطرفين بالترتيب
    messages = Message.query.filter(
        ((Message.sender_id == session['user_id']) & (Message.receiver_id == friend_id)) |
        ((Message.sender_id == friend_id) & (Message.receiver_id == session['user_id']))
    ).order_by(Message.timestamp.asc()).all()

    # تحديث الرسايل لتصبح "مقروءة" بمجرد فتح الشات
    unread = Message.query.filter_by(sender_id=friend_id, receiver_id=session['user_id'], is_read=False).all()
    for m in unread: m.is_read = True
    db.session.commit()

    return render_template('chat.html', friend=friend, messages=messages)

@socketio.on('send_message')
def handle_send_message(data):
    if not isinstance(data, dict):
        return
    sender_id = session.get('user_id')
    try:
        receiver_id = int(data.get('receiver_id'))
    except (TypeError, ValueError):
        return
    content = (data.get('content') or '').strip()[:500]
    if not sender_id or sender_id == receiver_id or not content or not db.session.get(User, receiver_id):
        return

    new_msg = Message(sender_id=sender_id, receiver_id=receiver_id, content=content)
    db.session.add(new_msg)
    db.session.commit()
    msg_data = {
        'id': new_msg.id,
        'content': content,
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'sender_name': db.session.get(User, sender_id).username,
        'timestamp': new_msg.timestamp.strftime('%I:%M %p')
    }
    socketio.emit('receive_message', msg_data, room=f"user_{receiver_id}")
    socketio.emit('receive_message', msg_data, room=f"user_{sender_id}")

# 1. حذف رسالة معينة
@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session: return redirect('/login')
    msg = db.session.get(Message, message_id)
    if msg and msg.sender_id == session['user_id']:
        friend_id = msg.receiver_id
        db.session.delete(msg)
        db.session.commit()
        return redirect(url_for('chat', friend_id=friend_id))
    return 'Message not found or not owned by the current user', 404

# 2. تعديل رسالة (سنستخدم POST لاستقبال النص الجديد)
@app.route('/edit_message/<int:message_id>', methods=['POST'])
def edit_message(message_id):
    if 'user_id' not in session: return redirect('/login')
    msg = db.session.get(Message, message_id)
    new_content = (request.form.get('content') or '').strip()
    if not msg or msg.sender_id != session['user_id']:
        return 'Message not found or not owned by the current user', 404
    if not new_content or len(new_content) > 500:
        return 'Invalid message content', 400
    if msg and msg.sender_id == session['user_id']:
        friend_id = msg.receiver_id
        msg.content = new_content + ' (معدلة)'
        db.session.commit()
    return '', 204

# 3. حذف الشات بالكامل بين شخصين
@app.route('/delete_chat/<int:friend_id>', methods=['POST'])
def delete_chat(friend_id):
    if 'user_id' not in session: return redirect('/login')
    user_id = session['user_id']
    # حذف كل الرسايل اللي بين الطرفين
    Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == friend_id)) |
        ((Message.sender_id == friend_id) & (Message.receiver_id == user_id))
    ).delete()
    db.session.commit()
    return redirect('/inbox')

@socketio.on('connect')
def handle_connect(auth=None):
    user_id = session.get('user_id')
    user = db.session.get(User, user_id) if user_id else None
    if not user or user.is_blocked:
        return False

    user.is_online_status = True
    user.last_seen = datetime.utcnow()
    db.session.commit()
    with state_lock:
        socket_user_ids[request.sid] = user.id
        active_user_sids.setdefault(user.id, set()).add(request.sid)
    join_room(f"user_{user.id}")
    socketio.emit('friend_status_change', {'user_id': user.id, 'online': True})


@socketio.on('disconnect')
def handle_disconnect(reason=None):
    with state_lock:
        user_id = socket_user_ids.pop(request.sid, None)
        if not user_id:
            return
        sids = active_user_sids.get(user_id, set())
        sids.discard(request.sid)
        if sids:
            return
        active_user_sids.pop(user_id, None)
    user = db.session.get(User, user_id)
    if user:
        user.is_online_status = False
        user.last_seen = datetime.utcnow()
        db.session.commit()
    socketio.emit('friend_status_change', {'user_id': user_id, 'online': False})


@socketio.on('presence_heartbeat')
def handle_presence_heartbeat():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id) if user_id else None
    if user:
        user.last_seen = datetime.utcnow()
        user.is_online_status = True
        db.session.commit()


@socketio.on('send_invite')
def handle_invite(data):
    if not isinstance(data, dict):
        return
    sender_id = session.get('user_id')
    lobby_id = str(data.get('lobby_id', ''))
    try:
        target_id = int(data.get('target_id'))
    except (TypeError, ValueError):
        emit('invite_error', {'message': 'تعذر إرسال الدعوة'})
        return

    friendship = Friend.query.filter_by(
        user_id=sender_id, friend_id=target_id, status='accepted'
    ).first()
    target = db.session.get(User, target_id)
    sender = db.session.get(User, sender_id) if sender_id else None
    if not sender or not target or not friendship or sender_id == target_id:
        emit('invite_error', {'target_id': target_id, 'message': 'يمكن دعوة الأصدقاء فقط'})
        return
    if not target.is_online:
        emit('invite_error', {'target_id': target_id, 'message': 'الصديق غير متصل الآن'})
        return

    with state_lock:
        room = lobby_rooms.get(lobby_id)
        if not room or room['host_id'] != sender_id or room['state'] != 'waiting':
            emit('invite_error', {'target_id': target_id, 'message': 'الغرفة غير متاحة للدعوة'})
            return
        if target_id in room['players'] or target_id in room['invited_ids']:
            emit('invite_error', {'target_id': target_id, 'message': 'تمت دعوة هذا اللاعب بالفعل'})
            return
        room['invited_ids'].add(target_id)

    socketio.emit('receive_invite', {
        'sender_name': sender.username,
        'lobby_id': lobby_id
    }, room=f"user_{target_id}")
    emit('invite_sent', {'target_id': target_id})


def _safe_answers(raw_answers):
    if not isinstance(raw_answers, list):
        return [''] * 6
    return [str(answer or '').strip()[:80] for answer in raw_answers[:6]] + [''] * max(0, 6 - len(raw_answers))


def _normalize_arabic(value):
    value = unicodedata.normalize('NFKC', str(value or '')).casefold()
    value = ''.join(char for char in value if char != '\u0640' and not unicodedata.combining(char))
    return value.translate(str.maketrans({'أ': 'ا', 'إ': 'ا', 'آ': 'ا', 'ٱ': 'ا'}))


def _score_round(players_answers, letter):
    scores = {}
    normalized_letter = _normalize_arabic(letter)
    for player_id, player_data in players_answers.items():
        answers = player_data['answers']
        total = 0
        for category_index, answer in enumerate(answers):
            normalized = _normalize_arabic(answer)
            if not normalized or normalized[0] != normalized_letter:
                continue
            duplicate_count = sum(
                1 for other in players_answers.values()
                if category_index < len(other['answers'])
                and other['answers'][category_index]
                and _normalize_arabic(other['answers'][category_index]) == normalized
            )
            total += 5 if duplicate_count > 1 else 10
        scores[player_id] = total
    return scores


def _finish_round(lobby_id, game_token):
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        game = room.get('game') if room else None
        if not game or game['token'] != game_token or game['status'] == 'finished':
            return
        participants = dict(game['participants'])
        answers = dict(game['answers'])
        for player_id, username in participants.items():
            answers.setdefault(player_id, {'username': username, 'answers': [''] * 6})
        game['status'] = 'finished'
        game['answers'] = answers

    scores = _score_round(answers, game['letter'])
    leaderboard = []
    with app.app_context():
        try:
            for player_id, points in scores.items():
                player = db.session.get(User, player_id)
                if player:
                    player.points = (player.points or 0) + points
                    leaderboard.append([player.username, points])
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Could not save game scores for lobby %s", lobby_id)
            leaderboard = [[answers[player_id]['username'], points] for player_id, points in scores.items()]

    leaderboard.sort(key=lambda row: (-row[1], row[0].casefold()))
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        game = room.get('game') if room else None
        if game and game['token'] == game_token:
            game['leaderboard'] = leaderboard
            game['finished_at'] = datetime.utcnow()
            room['state'] = 'finished'
    socketio.emit('game_ended', {'reason': 'finished'}, room=lobby_id)
    socketio.emit('show_results', {'leaderboard': leaderboard}, room=lobby_id)
    socketio.start_background_task(_cleanup_lobby_later, lobby_id, game_token)


def _cleanup_lobby_later(lobby_id, game_token):
    socketio.sleep(900)
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        game = room.get('game') if room else None
        if game and game['token'] == game_token and game['status'] == 'finished':
            lobby_rooms.pop(lobby_id, None)


def _game_deadline_worker(lobby_id, game_token, timer):
    socketio.sleep(timer)
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        game = room.get('game') if room else None
        if not game or game['token'] != game_token or game['status'] == 'finished':
            return
        game['ending'] = True
    socketio.emit('game_submission_requested', {'reason': 'time_up'}, room=lobby_id)
    socketio.sleep(1.5)
    _finish_round(lobby_id, game_token)


def _early_finish_worker(lobby_id, game_token):
    socketio.sleep(3)
    _finish_round(lobby_id, game_token)


@socketio.on('join_lobby')
def handle_join_lobby(data):
    if not isinstance(data, dict):
        return
    user_id = session.get('user_id')
    user = db.session.get(User, user_id) if user_id else None
    lobby_id = str(data.get('room', ''))
    if not user:
        emit('lobby_error', {'message': 'سجّل الدخول للانضمام'})
        return

    if lobby_id.startswith('user_'):
        try:
            requested_user_id = int(lobby_id.removeprefix('user_'))
        except ValueError:
            return
        if requested_user_id == user.id:
            join_room(lobby_id)
        return

    with state_lock:
        room = lobby_rooms.get(lobby_id)
        if not room or user.id not in room['players']:
            emit('lobby_error', {'message': 'ليس لديك صلاحية دخول هذه الغرفة'})
            return
        is_new_player = user.id not in room['connected_ids']
        room['players'][user.id] = user.username
        room['connected_ids'].add(user.id)
        room_state = {
            'players': [{'id': player_id, 'username': username}
                        for player_id, username in room['players'].items()],
            'host_id': room['host_id'],
            'state': room['state']
        }
        game = room.get('game')

    join_room(lobby_id)
    emit('lobby_state', room_state)
    if is_new_player:
        socketio.emit('player_joined', {'user_id': user.id, 'username': user.username}, room=lobby_id, skip_sid=request.sid)
    if game and game['status'] == 'playing':
        emit('redirect_to_game', {
            'lobby_id': lobby_id,
            'timer': max(0, int(game['end_at'] - datetime.utcnow().timestamp())),
            'letter': game['letter']
        })
    elif game and game['status'] == 'finished' and game.get('leaderboard') is not None:
        emit('show_results', {'leaderboard': game['leaderboard']})


@socketio.on('start_game_event')
def handle_start_game(data):
    if not isinstance(data, dict):
        return
    user_id = session.get('user_id')
    lobby_id = str(data.get('lobby_id', ''))
    try:
        timer = int(data.get('timer', 60))
    except (TypeError, ValueError):
        timer = 60
    timer = timer if timer in (30, 60, 90) else 60
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        if not room or room['host_id'] != user_id or room['state'] != 'waiting':
            emit('lobby_error', {'message': 'المضيف فقط يمكنه بدء الجولة'})
            return
        letter = random.choice(ARABIC_LETTERS)
        token = str(uuid.uuid4())
        participants = dict(room['players'])
        room['state'] = 'playing'
        room['game'] = {
            'token': token,
            'status': 'playing',
            'timer': timer,
            'letter': letter,
            'participants': participants,
            'answers': {},
            'ending': False,
            'started_at': datetime.utcnow(),
            'end_at': datetime.utcnow().timestamp() + timer,
            'leaderboard': None
        }

    socketio.emit('redirect_to_game', {
        'lobby_id': lobby_id,
        'timer': timer,
        'letter': letter
    }, room=lobby_id)
    socketio.start_background_task(_game_deadline_worker, lobby_id, token, timer)


def _record_submission(data, early_finish=False):
    if not isinstance(data, dict):
        return
    user_id = session.get('user_id')
    lobby_id = str(data.get('lobby_id', ''))
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        game = room.get('game') if room else None
        if not game or game['status'] != 'playing' or user_id not in game['participants']:
            return
        game['answers'][user_id] = {
            'username': game['participants'][user_id],
            'answers': _safe_answers(data.get('answers'))
        }
        if early_finish and not game['ending']:
            game['ending'] = True
            should_request_others = True
            token = game['token']
        else:
            should_request_others = False
            token = game['token']
        all_submitted = len(game['answers']) >= len(game['participants'])

    if should_request_others:
        socketio.emit('game_submission_requested', {'reason': 'player_finished'}, room=lobby_id)
        if all_submitted:
            _finish_round(lobby_id, token)
        else:
            socketio.start_background_task(_early_finish_worker, lobby_id, token)
    elif all_submitted and game.get('ending'):
        _finish_round(lobby_id, token)


@socketio.on('player_finished')
def handle_finish(data):
    _record_submission(data, early_finish=True)


@socketio.on('time_up')
def handle_time_up(data):
    _record_submission(data, early_finish=False)


@socketio.on('kick_player')
def handle_kick_player(data):
    if not isinstance(data, dict):
        return
    host_id = session.get('user_id')
    lobby_id = str(data.get('lobby_id', ''))
    try:
        kicked_id = int(data.get('user_id'))
    except (TypeError, ValueError):
        return
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        if not room or room['host_id'] != host_id or room['state'] != 'waiting' or kicked_id == host_id:
            return
        username = room['players'].pop(kicked_id, None)
        if not username:
            return
        room['invited_ids'].discard(kicked_id)
        target_sids = list(active_user_sids.get(kicked_id, set()))
    for sid in target_sids:
        leave_room(lobby_id, sid=sid)
    socketio.emit('you_were_kicked', {}, room=f"user_{kicked_id}")
    socketio.emit('player_left', {'user_id': kicked_id, 'username': username}, room=lobby_id)


@socketio.on('game_chat')
def handle_game_chat(data):
    if not isinstance(data, dict):
        return
    user_id = session.get('user_id')
    lobby_id = str(data.get('room', ''))
    message = (data.get('message') or '').strip()[:300]
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        allowed = room and room['state'] == 'playing' and user_id in room['players']
        username = room['players'].get(user_id) if allowed else None
    if allowed and message:
        socketio.emit('receive_game_chat', {'user': username, 'message': message}, room=lobby_id)

def create_lobby(lobby_id, host):
    with state_lock:
        lobby_rooms[lobby_id] = {
            'host_id': host.id,
            'players': {host.id: host.username},
            'connected_ids': set(),
            'invited_ids': set(),
            'state': 'waiting',
            'game': None
        }


@app.route('/play/<lobby_id>')
@login_required
def lobby(lobby_id):
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        if not room or current_user.id not in room['players'] and current_user.id not in room['invited_ids']:
            flash("الغرفة غير موجودة أو انتهت صلاحيتها")
            return redirect(url_for('dashboard'))
        if room['state'] == 'playing':
            game = room['game']
            return redirect(url_for('game_page', lobby_id=lobby_id, timer=game['timer'], letter=game['letter']))

    friend_conns = Friend.query.filter_by(user_id=current_user.id, status='accepted').all()
    friends_list = [
        friend_user
        for conn in friend_conns
        if (friend_user := db.session.get(User, conn.friend_id)) is not None
    ]
    return render_template(
        'lobby.html',
        user=current_user,
        friends=friends_list,
        lobby_id=lobby_id,
        is_host=current_user.id == room['host_id']
    )

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/start_new_game', methods=['POST'])
@login_required
def start_new_game():
    new_lobby_id = str(uuid.uuid4())[:8]
    create_lobby(new_lobby_id, current_user)
    return redirect(url_for('lobby', lobby_id=new_lobby_id))


@app.route('/challenge/<int:friend_id>', methods=['POST'])
@login_required
def challenge_friend(friend_id):
    friend_link = Friend.query.filter_by(
        user_id=current_user.id, friend_id=friend_id, status='accepted'
    ).first()
    friend = db.session.get(User, friend_id)
    if not friend_link or not friend or friend_id == current_user.id:
        flash("يمكنك تحدي أصدقائك فقط")
        return redirect(url_for('friends'))
    if not friend.is_online:
        flash(f"{friend.username} غير متصل الآن")
        return redirect(url_for('friends'))

    lobby_id = str(uuid.uuid4())[:8]
    create_lobby(lobby_id, current_user)
    with state_lock:
        lobby_rooms[lobby_id]['invited_ids'].add(friend_id)
    socketio.emit('receive_invite', {
        'sender_name': current_user.username,
        'lobby_id': lobby_id
    }, room=f"user_{friend_id}")
    return redirect(url_for('lobby', lobby_id=lobby_id))

@app.route('/join_lobby/<lobby_id>', methods=['POST'])
@login_required
def join_lobby(lobby_id):
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        if not room or current_user.id not in room['invited_ids']:
            flash("الدعوة غير موجودة أو انتهت صلاحيتها")
            return redirect(url_for('dashboard'))
        room['players'][current_user.id] = current_user.username
        room['invited_ids'].discard(current_user.id)
    return redirect(url_for('lobby', lobby_id=lobby_id))

@app.route('/game/<lobby_id>')
@login_required
def game_page(lobby_id):
    with state_lock:
        room = lobby_rooms.get(lobby_id)
        game = room.get('game') if room else None
        if not room or current_user.id not in room['players'] or not game:
            flash("الجولة غير متاحة لهذا الحساب")
            return redirect(url_for('dashboard'))
        timer = max(0, int(game['end_at'] - datetime.utcnow().timestamp()))
        letter = game['letter']
    return render_template('game.html', lobby_id=lobby_id, timer=timer, letter=letter, user=current_user)

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    if not isinstance(data, dict):
        return
    user_id = session.get('user_id')
    try:
        friend_id = int(data.get('friend_id'))
    except (TypeError, ValueError):
        return
    if not user_id:
        return

    Message.query.filter_by(
        sender_id=friend_id,
        receiver_id=user_id,
        is_read=False
    ).update({Message.is_read: True}, synchronize_session=False)
    db.session.commit()
    socketio.emit('messages_seen', {'seen_by': user_id}, room=f"user_{friend_id}")

@socketio.on('typing')
def handle_typing(data):
    if not isinstance(data, dict):
        return
    friend_id = data.get('friend_id')
    user_id = session.get('user_id')
    if not user_id:
        return
    try:
        friend_id = int(friend_id)
    except (TypeError, ValueError):
        return
    socketio.emit('display_typing', {
        'user_id': user_id,
        'is_typing': bool(data.get('is_typing'))
    }, room=f"user_{friend_id}")

@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/favicon.ico')
def serve_favicon():
    return send_from_directory('static', 'favicon.svg', mimetype='image/svg+xml')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, log_output=True)