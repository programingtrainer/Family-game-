import os
import random
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, delete, select
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

ARABIC_LETTERS = ['أ', 'ب', 'ت', 'ث', 'ج', 'ح', 'خ', 'د', 'ذ', 'ر', 'ز', 'س', 'ش', 'ص', 'ض', 'ط', 'ظ', 'ع', 'غ', 'ف', 'ق', 'ك', 'ل', 'م', 'ن', 'هـ', 'و', 'ي']

app = Flask(__name__)
app.config['SECRET_KEY'] = 'FamilyGame_Secret_123'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///familygame_vFinal.db'
socketio = SocketIO(app)
socketio = SocketIO(app, cors_allowed_origins="*")

game_results = {}

db = SQLAlchemy(app)

# 1. إعداد LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # اسم الـ route بتاع صفحة الدخول عندك

# --- تعريف الجداول ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    level = db.Column(db.Integer, default=1)
    points = db.Column(db.Integer, default=0)
    is_blocked = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    bio = db.Column(db.String(200), default="لاعب جديد في FamilyGame") # هل دي كانت موجودة؟
    avatar = db.Column(db.String(200), default="default.png") # وهل دي؟
    
    @property
    def is_online(self):
        if self.last_seen:
            now = datetime.utcnow()
            duration = (now - self.last_seen).total_seconds()
            return duration < 60
        return False
    
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
    is_read = db.Column(db.Boolean, default=False) # عشان العلامة الحمراء زي واتساب

    # علاقات عشان نجيب بيانات المرسل والمستقبل بسهولة
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# إنشاء قاعدة البيانات بالحقول الجديدة
with app.app_context():
    db.create_all()

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

@app.route('/add_friend/<int:friend_id>')
def add_friend(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    exists = Friend.query.filter_by(user_id=session['user_id'], friend_id=friend_id).first()
    if not exists:
        new_friend = Friend(user_id=session['user_id'], friend_id=friend_id)
        db.session.add(new_friend)
        db.session.commit()
    return redirect(url_for('friends'))

# --- Routes الدخول والتسجيل ---

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user_name = request.form.get('username')
        pass_word = request.form.get('password')
        confirm_pwd = request.form.get('confirm_password')

        if pass_word != confirm_pwd:
            return render_template('signup.html', error="كلمات السر غير متطابقة")

        existing_user = User.query.filter_by(username=user_name).first()
        if existing_user:
            return render_template('signup.html', error="الاسم موجود مسبقاً")

        hashed_password = generate_password_hash(pass_word)
        new_user = User(username=user_name, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_name = request.form.get('username')
        pass_word = request.form.get('password')
        user_captcha = request.form.get('captcha_answer')
        correct_captcha = session.get('captcha_result')

        # 1. فحص الكاباتشا
        if not user_captcha or int(user_captcha) != correct_captcha:
            num1, num2 = random.randint(1, 10), random.randint(1, 10)
            session['captcha_result'] = num1 + num2
            return render_template('login.html', error="إجابة الكاباتشا غلط", num1=num1, num2=num2)

        # 2. البحث عن المستخدم
        user = User.query.filter_by(username=user_name).first()

        if user:
            password_valid = False
            
            # Check if password is hashed (starts with common hash prefixes)
            if user.password.startswith(('pbkdf2:', 'scrypt:', 'sha256$')):
                password_valid = check_password_hash(user.password, pass_word)
            else:
                # Plain text password (old users) - check directly then upgrade
                if user.password == pass_word:
                    password_valid = True
                    # Upgrade to hashed password
                    user.password = generate_password_hash(pass_word)
                    db.session.commit()
            
            if password_valid:
                if user.is_blocked:
                    num1, num2 = random.randint(1, 10), random.randint(1, 10)
                    session['captcha_result'] = num1 + num2
                    return render_template('login.html', error="حسابك محظور من الإدارة", num1=num1, num2=num2)

                login_user(user, remember=True) 
                session['user_id'] = user.id
                session['username'] = user.username
                return redirect(url_for('dashboard'))

        num1, num2 = random.randint(1, 10), random.randint(1, 10)
        session['captcha_result'] = num1 + num2
        return render_template('login.html', error="اسم المستخدم أو كلمة المرور غلط", num1=num1, num2=num2)

    # للجزء الـ GET
    num1, num2 = random.randint(1, 10), random.randint(1, 10)
    session['captcha_result'] = num1 + num2
    return render_template('login.html', num1=num1, num2=num2)

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

@app.route('/logout')
def logout():
    session.clear()
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

@app.route('/delete_account')
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if user:
        Friend.query.filter((Friend.user_id == user.id) | (Friend.friend_id == user.id)).delete()
        db.session.delete(user)
        db.session.commit()
        session.clear()
    return redirect(url_for('welcome'))

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

@app.route('/toggle_block/<int:user_id>')
def toggle_block(user_id):
    admin = db.session.get(User, session.get('user_id'))
    if not admin or admin.username != 'gatapro901':
        return "Unauthorized", 403
    target = db.session.get(User, user_id)
    if target:
        target.is_blocked = not target.is_blocked
        db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin_delete_user/<int:user_id>')
def admin_delete_user(user_id):
    admin = db.session.get(User, session.get('user_id'))
    if not admin or admin.username != 'gatapro901':
        return "Unauthorized", 403
    target = db.session.get(User, user_id)
    if target:
        db.session.delete(target)
        db.session.commit()
    return redirect(url_for('admin_panel'))

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

@app.route('/accept_friend/<int:request_id>')
def accept_friend(request_id):
    if 'user_id' not in session: return redirect(url_for('login'))

    req = db.session.get(Friend, request_id)
    if req and req.friend_id == session['user_id']:
        # 1. تحديث حالة الطلب الأصلي
        req.status = 'accepted'

        # 2. إنشاء علاقة عكسية عشان الطرفين يشوفوا بعض (مهم جداً)
        reverse_friend = Friend(user_id=session['user_id'], friend_id=req.user_id, status='accepted')
        db.session.add(reverse_friend)

        # 3. إرسال الإشعار للشخص اللي بعت الطلب (req.user_id)
        # احنا هنا بنقول: يا قاعدة بيانات، حطي رسالة في جرس الشخص اللي "بدأ" الإضافة
        new_note = Notification(
            user_id=req.user_id, 
            message=f"وافق {session['username']} على طلب صداقتك 🎉"
        )
        db.session.add(new_note)

        # 4. حفظ كل التغييرات في خطوة واحدة
        db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/reject_friend/<int:request_id>')
def reject_friend(request_id):
    if 'user_id' not in session: return redirect(url_for('login'))

    req = db.session.get(Friend, request_id)
    if req and req.friend_id == session['user_id']:
        db.session.delete(req)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/unfriend/<int:friend_id>')
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
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
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

@app.route('/send_message/<int:receiver_id>', methods=['POST'])
def send_message(receiver_id):
    if 'user_id' not in session: return redirect('/login')

    content = request.form.get('content')
    if content:
        new_msg = Message(sender_id=session['user_id'], receiver_id=receiver_id, content=content)
        db.session.add(new_msg)
        db.session.commit()

    return redirect(f'/chat/{receiver_id}')

# 1. حذف رسالة معينة
@app.route('/delete_message/<int:message_id>')
def delete_message(message_id):
    if 'user_id' not in session: return redirect('/login')
    msg = db.session.get(Message, message_id)
    # التأكد إن اللي بيحذف هو اللي بعت الرسالة
    if msg and msg.sender_id == session['user_id']:
        db.session.delete(msg)
        db.session.commit()
    return redirect(request.referrer)

# 2. تعديل رسالة (سنستخدم POST لاستقبال النص الجديد)
@app.route('/edit_message/<int:message_id>', methods=['POST'])
def edit_message(message_id):
    if 'user_id' not in session: return redirect('/login')
    msg = db.session.get(Message, message_id)
    new_content = request.form.get('content')
    if msg and msg.sender_id == session['user_id'] and new_content:
        msg.content = new_content + " (معدلة)" # إضافة كلمة معدلة للشفافية
        db.session.commit()
    return redirect(request.referrer)

# 3. حذف الشات بالكامل بين شخصين
@app.route('/delete_chat/<int:friend_id>')
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
def handle_connect():
    # هنا بنربط اسم المستخدم بالـ ID بتاع الاتصال بتاعه
    # user_id = current_user.id (لو بتستخدم Flask-Login)
    # online_users[user_id] = request.sid
    print("لاعب جديد اتصل بالسيستم")

@socketio.on('send_invite')
def handle_invite(data):
    # التأكد من أن target_id يصل كـ string أو int حسب قاعدة بياناتك
    target_friend_id = data['target_id']
    sender_name = data['sender_name']
    lobby_id = data['lobby_id']

    # إرسال التنبيه لغرفة المستخدم المستهدف فقط
    emit('receive_invite', {
        'sender_name': sender_name,
        'lobby_id': lobby_id
    }, room=f"user_{target_friend_id}")

@socketio.on('accept_invite')
def handle_accept(data):
    lobby_id = data['lobby_id']
    username = data['username'] # اسم الصديق اللي وافق

    # نبعث لكل اللي في الأوضة إن فيه بطل جديد انضم
    emit('player_joined', {'username': username}, room=lobby_id)

@app.route('/play/<lobby_id>')
@login_required 
def lobby(lobby_id):
    friend_conns = Friend.query.filter_by(user_id=current_user.id, status='accepted').all()
    friends_list = []
    for f in friend_conns:
        friend_user = db.session.get(User, f.friend_id)
        if friend_user:
            # هنضيف حالة الـ online وهمياً دلوقتي أو لو عندك column ليها
            friends_list.append(friend_user)

    # بنقرأ هل هو مضيف من الرابط
    is_host = request.args.get('host', 'false') == 'true'

    return render_template('lobby.html', 
                           user=current_user, 
                           friends=friends_list, 
                           lobby_id=lobby_id, 
                           is_host=is_host)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@socketio.on('player_joined_lobby')
def handle_player_joined_lobby(data):
    lobby_id = data['lobby_id']
    username = data['username']
    user_id = data.get('user_id', '')
    emit('player_joined', {'username': username, 'user_id': user_id}, room=lobby_id, include_self=False)
    print(f"Broadcasted: {username} joined {lobby_id}")

@socketio.on('start_game_event')
def handle_start_game(data):
    lobby_id = data['lobby_id']
    timer_value = data['timer'] # الوقت اللي أنت حددته (مثلاً 60 ثانية)

    # اختيار حرف عشوائي للجولة الأولى
    selected_letter = random.choice(ARABIC_LETTERS)

    # إرسال أمر البدء لكل اللاعبين في الغرفة
    emit('redirect_to_game', {
        'lobby_id': lobby_id,
        'timer': timer_value,
        'letter': selected_letter
    }, room=lobby_id)

@socketio.on('reject_invite')
def handle_reject(data):
    host_id = data['host_id']
    rejecter_name = data['rejecter_name']

    # نبعت للمضيف إن فلان رفض في غرفته الخاصة (user_ID)
    emit('invite_rejected', {
        'msg': f"للأسف، {rejecter_name} رفض التحدي بتاعك."
    }, room=f"user_{host_id}")

@app.route('/start_new_game')
@login_required
def start_new_game():
    new_lobby_id = str(uuid.uuid4())[:8]
    return redirect(url_for('lobby', lobby_id=new_lobby_id, host='true'))

@app.route('/join_lobby/<lobby_id>')
@login_required
def join_lobby(lobby_id):
    return redirect(url_for('lobby', lobby_id=lobby_id, host='false'))

@socketio.on('join_lobby')
def handle_join_lobby(data):
    room = data['room']
    join_room(room)
    print(f"User joined room: {room}")

@socketio.on('kick_player')
def handle_kick_player(data):
    lobby_id = data['lobby_id']
    kicked_username = data['username']
    emit('you_were_kicked', {}, room=f"user_{data['user_id']}")
    emit('player_left', {'username': kicked_username}, room=lobby_id)

@app.route('/game/<lobby_id>')
@login_required
def game_page(lobby_id):
    timer = request.args.get('timer', 60)
    letter = request.args.get('letter', 'أ')
    return render_template('game.html', lobby_id=lobby_id, timer=timer, letter=letter, user=current_user)

@socketio.on('game_chat')
def handle_game_chat(data):
    emit('receive_game_chat', data, room=data['room'])

# 1. الدالة اللي بتستقبل الإجابات وتقفل اللعب عند الباقي
@socketio.on('player_finished')
def handle_finish(data):
    lobby_id = data['lobby_id']
    username = data['username']
    answers = data['answers']
    # الحرف اللي كان شغال في الجولة دي (ممكن تبعته من الـ JS أو تحفظه في السيرفر)
    current_letter = data.get('letter', 'أ') 

    if lobby_id not in game_results:
        game_results[lobby_id] = {}

    # حفظ إجابات اللاعب اللي خلص
    game_results[lobby_id][username] = answers

    # إبلاغ الكل إن اللعب وقف فوراً
    emit('stop_game_for_all', {'winner': username}, room=lobby_id)

    # ابدأ الحساب (هنا بنادي دالة الحساب اللي تحت)
    calculate_scores(lobby_id, current_letter)

# 2. دالة الحساب (دي دالة داخلية مش محتاجة @socketio.on)
def calculate_scores(lobby_id, current_letter):
    if lobby_id not in game_results:
        return

    all_players_data = game_results[lobby_id]
    final_scores = {user: 0 for user in all_players_data.keys()}

    # بنلف على الـ 6 خانات (ولد، بنت، حيوان، إلخ)
    for i in range(6):
        category_answers = []

        # تجميع الكلمات اللي بتبدأ بالحرف الصح بس
        for user in all_players_data:
            ans = all_players_data[user][i].strip()
            if ans and ans.startswith(current_letter):
                category_answers.append(ans)

        # توزيع الـ 10 والـ 5
        for user in all_players_data:
            user_ans = all_players_data[user][i].strip()

            if not user_ans or not user_ans.startswith(current_letter):
                points = 0
            elif category_answers.count(user_ans) > 1:
                points = 5  # متكررة
            else:
                points = 10 # فريدة

            final_scores[user] += points

    # إرسال النتائج النهائية للكل في اللوبي
    emit('show_results', {'scores': final_scores}, room=lobby_id)

    # مسح الذاكرة للجولة الجاية
    del game_results[lobby_id]

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=True, log_output=True)