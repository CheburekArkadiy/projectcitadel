import os

from flask import Flask, render_template, redirect, request, abort, jsonify
from data import db_session
from data.loginfrom import LoginForm
from werkzeug.security import check_password_hash, generate_password_hash
from data.users import User
from flask_login import LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, EmailField
from wtforms.validators import DataRequired
from flask_login import login_user
from sqlalchemy.sql import func
from data.users import RegisterForm
import requests
from flask_restful import reqparse, abort, Api, Resource
from flask import make_response
from flask import url_for
from werkzeug.utils import secure_filename
import random
import smtplib

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'it_starts_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


# Проверка, на расширение файла #
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


# Вспомогательная функция для загрузки пользователей #
@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    db_sess.close()
    return db_sess.query(User).get(user_id)


# Начальная Страница #
@app.route("/")
def index():
    return render_template("startpage.html")


# Вход в аккаунт #
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            print(user)
            login_user(user, remember=form.remember_me.data)
            db_sess.close()
            return redirect("/mainpage")
        db_sess.close()
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


# РЕГИСТРАЦИЯ #
@app.route('/registration', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пользователь с таким адресом электронной почты уже зарегистрирован")
        user = User(
            email=form.email.data,
            name=form.name.data,
            surname=form.surname.data,
            city=form.city.data,
            school=form.school.data,
            avatar='static/img/profile.jpg',
        )
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        db_sess.close()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form,
                           title2='Регистрация для учителя')


# Выход из аккаунта #
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/login")




# Страница с контактной информацией #
@app.route('/contacts', methods=['GET'])
def contacts():
    db_sess = db_session.create_session()
    user = db_sess.query(User)
    db_sess.close()
    return render_template('contacts.html')


# Страница, для выбора роли при регистрации #
@app.route('/register-choose', methods=['GET'])
def choose_role():
    if current_user.is_authenticated:
        return redirect('/redirect-people')
    else:
        return render_template('vybor_roli.html')

# Блок проверки на ошибки #
@app.errorhandler(404)
def not_found(error):
    return render_template('4041.html')


@app.errorhandler(500)
def oshibka(error):
    return redirect('/')


@app.errorhandler(401)
def oshibka(error):
    return redirect('/')


@app.errorhandler(400)
def bad_request(_):
    return render_template('badrequetsik.html')

# Конец блока проверки на ошибки #

# Профиль пользователя #
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db_sess = db_session.create_session()
    users = db_sess.query(User).filter(User.id == current_user.id).first()
    users_fio = users.surname.capitalize() + ' ' + users.name.capitalize()
    users_name = users.name.capitalize()
    users_email = users.email
    avatar = users.avatar
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            db_sess = db_session.create_session()
            file.save(os.path.join(UPLOAD_FOLDER, str(current_user.id) + '.jpg'))
            db_sess = db_session.create_session()
            users = db_sess.query(User).filter(User.id == current_user.id).first()
            users.avatar = 'static/uploads/' + str(current_user.id) + '.jpg'
            db_sess.commit()
            db_sess.close()
        return redirect('/profile')
    db_sess.close()
    return render_template('profile2.html', fio=users_fio, name=users_name, email=users_email, avatar=avatar, user=users)


@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = RegisterForm()
    if request.method == "GET":
        db_sess = db_session.create_session()
        users = db_sess.query(User).filter(User.id == current_user.id).first()
        if users and users is not None:
            form.email.data = users.email
            form.name.data = users.name
            form.surname.data = users.surname
            form.city.data  = users.city
            form.school.data  = users.school
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        db_sess = db_session.create_session()
        users = db_sess.query(User).filter(User.id == current_user.id).first()
        if db_sess.query(User).filter(User.email == form.email.data).first() and users.email != form.email.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пользователь с таким адресом электронной почты уже зарегистрирован")
        users.email = form.email.data
        users.city = form.city.data
        users.school = form.school.data
        users.name = form.name.data
        users.surname = form.surname.data
        password = generate_password_hash(form.password.data)
        users.hashed_password = password
        db_sess.commit()
        db_sess.close()
        return redirect('/profile')
    return render_template('register.html',
                           title='Редактирование Профиля',
                           form=form, url1='/profile', current_user=current_user)



@app.route('/edit-photo', methods=['GET', 'POST'])
@login_required
def edit_photo():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            db_sess = db_session.create_session()
            file.save(os.path.join(UPLOAD_FOLDER, str(current_user.id) + '.jpg'))
            db_sess.close()
        return redirect('/profile')
    return render_template('edit_photo.html')


@app.route('/mainpage')
@login_required
def mainpage():
    all_points1 = 0
    db_sess = db_session.create_session()
    all_points = db_sess.query(User)
    for point in all_points:
        all_points1 += int(point.points)
    print(all_points1)
    need_now = 5000000
    procent = ((all_points1 * 100) // need_now)
    show_podskazka = False
    if procent >= 100:
        procent=100
        show_podskazka = True
    return render_template('main_page.html', all_points=all_points1, procent=procent, need_now=need_now, sp = show_podskazka)

# Запуск приложения #
if __name__ == '__main__':
    db_session.global_init("db/alldata.db")
    app.run(threaded=True)
