import os
import random # ده هيحل مشكلة السطر 138 (random is not defined)
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, delete, select

app = Flask(__name__)
app.config['SECRET_KEY'] = 'FamilyGame_Secret_123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///familygame.db'

db = SQLAlchemy(app)

# تعريف جدول المستخدمين
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    # إضافة الـ Constructor لحل مشكلة الـ arguments
    def __init__(self, username, password):
        self.username = username
        self.password = password

# تأكد أن السطرين دول موجودين بعد تعريف الكلاس
with app.app_context():
    db.create_all()

# جدول الأصدقاء
class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, user_id, friend_id):
        self.user_id = user_id
        self.friend_id = friend_id

# تأكد من تحديث قاعدة البيانات في ريبليت
with app.app_context():
    db.create_all()

# --- Routes البحث وإضافة الأصدقاء ---

@app.route('/friends', methods=['GET', 'POST'])
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    search_results = []
    if request.method == 'POST':
        query = request.form.get('search_query')
       
        # الطريقة الصحيحة للبحث
        stmt = select(User).where(User.username.like(f'%{query}%'), User.id != session['user_id'])
        search_results = db.session.execute(stmt).scalars().all()

    # جلب قائمة الأصدقاء الحاليين بطريقة متوافقة
    friend_conns = Friend.query.filter_by(user_id=session['user_id']).all()
    my_friends = []
    for f in friend_conns:
        # استخدمنا db.session.get بدلاً من .get العادية
        friend_user = db.session.get(User, f.friend_id)
        if friend_user:
            my_friends.append(friend_user)

    return render_template('friends.html', results=search_results, my_friends=my_friends)

@app.route('/add_friend/<int:friend_id>')
def add_friend(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # التأكد من عدم وجود الصداقة مسبقاً
    exists = Friend.query.filter_by(
        user_id=session['user_id'], 
        friend_id=friend_id
    ).first()

    if not exists:
        new_friend = Friend(user_id=session['user_id'], friend_id=friend_id)
        db.session.add(new_friend)
        db.session.commit()

    return redirect(url_for('friends'))
    
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

        # الطريقة الحديثة للتحقق من وجود اسم المستخدم
        stmt = db.select(User).filter_by(username=user_name)
        existing_user = db.session.execute(stmt).scalar_one_or_none()

        if existing_user:
            return render_template('signup.html', error="الاسم موجود مسبقاً")

        new_user = User(username=user_name, password=pass_word)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_name = request.form.get('username')
        pass_word = request.form.get('password')
        # الحصول على إجابة المستخدم من الحقل اللي في الـ HTML
        user_captcha = request.form.get('captcha_answer')
        # الحصول على الإجابة الصحيحة من الجلسة
        correct_captcha = session.get('captcha_result')

        # أول خطوة: التأكد من الكاباتشا
        if not user_captcha or int(user_captcha) != correct_captcha:
            # لو غلط، نولد أرقام جديدة ونرجع صفحة اللوجن مع رسالة خطأ
            num1, num2 = random.randint(1, 10), random.randint(1, 10)
            session['captcha_result'] = num1 + num2
            return render_template('login.html', error="إجابة الكاباتشا غير صحيحة", num1=num1, num2=num2)

        # ثاني خطوة: البحث عن المستخدم
        stmt = select(User).where(User.username == user_name, User.password == pass_word)
        user = db.session.execute(stmt).scalar_one_or_none()

        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            # لو بيانات المستخدم غلط، نولد برضه كاباتشا جديدة للأمان
            num1, num2 = random.randint(1, 10), random.randint(1, 10)
            session['captcha_result'] = num1 + num2
            return render_template('login.html', error="بيانات الدخول غير صحيحة", num1=num1, num2=num2)

    # في حالة الـ GET (أول مرة يفتح الصفحة)
    num1, num2 = random.randint(1, 10), random.randint(1, 10)
    session['captcha_result'] = num1 + num2
    return render_template('login.html', num1=num1, num2=num2)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear() # مسح كل بيانات الجلسة
    return redirect(url_for('welcome'))

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/change_password', methods=['POST'])
def change_password():
    # 1. التأكد من تسجيل الدخول
    if 'user_id' not in session:
        return redirect(url_for('login'))

    new_pwd = request.form.get('new_password')
    confirm_pwd = request.form.get('confirm_password')

    # 2. جلب المستخدم والتأكد أنه ليس None
    user = db.session.get(User, session['user_id'])

    # لو السيرفر مش لاقي المستخدم، نرجعه لصفحة الدخول
    if user is None:
        return redirect(url_for('login'))

    # 3. التحقق من تطابق الحقول
    if not new_pwd or new_pwd.strip() == "":
        return render_template('settings.html', error="كلمة المرور فارغة!", user=user)

    if new_pwd != confirm_pwd:
        return render_template('settings.html', error="كلمات المرور غير متطابقة!", user=user)

    # 4. التحديث الفعلي (هنا اختفى خطأ الـ None)
    try:
        user.password = new_pwd  # الآن بايثون متأكد أن user ليس None
        db.session.commit()
        return render_template('settings.html', success="تم تغيير كلمة المرور بنجاح ✅", user=user)
    except Exception as e:
        db.session.rollback()
        return render_template('settings.html', error="حدث خطأ في قاعدة البيانات", user=user)
        
@app.route('/delete_account')
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    u_id = session['user_id']
    user = db.session.get(User, u_id)
    if user:
        # حذف علاقات الصداقة قبل حذف الحساب
        db.session.execute(delete(Friend).where(or_(Friend.user_id == u_id, Friend.friend_id == u_id)))
        db.session.delete(user)
        db.session.commit()
        session.clear()
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)