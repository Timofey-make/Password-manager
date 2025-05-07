import random
from flask import Flask, flash, render_template, redirect, url_for, session, request, abort
import sqlite3
from init import init_db
import function
import forms

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'veryverystrongkeypassword'


@app.route('/')
def slash():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register(error=None):
    if error is None:
        error = request.args.get('error', '')
    form = forms.RegisterForm()
    if form.validate_on_submit():
        hashed_password = function.hash_password(form.password.data)
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users ORDER BY id DESC LIMIT 1")
            last_user = cursor.fetchone()

            if last_user:
                new_id = last_user[0] + 1
            else:
                new_id = 1
        try:
            cursor.execute("INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
                           (new_id, form.username.data, hashed_password))
            conn.commit()
            flash('Регистрация прошла успешно!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return redirect(url_for("register", error='пользователь с таким логином уже есть', form=form))

    return render_template('register.html', form=form, error=error)


@app.route('/login', methods=['GET', 'POST'])
def login(error=None):
    if error is None:
        error = request.args.get('error', '')
    form = forms.LoginForm()
    if form.validate_on_submit():
        hashed_password = function.hash_password(form.password.data)
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username FROM users WHERE username = ? AND password = ?",
                           (form.username.data, hashed_password))
            user = cursor.fetchone()

        if user:
            session['user'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('personal_main'))
        else:
            return redirect(url_for("login", error="Неверный логин или пароль", form=form))
    return render_template('login.html', form=form, error=error)


@app.route("/password-generator", methods=["GET", "POST"])
@function.login_required
def generator():
    label = 'Ничего не сгенерировано'
    form = forms.GeneratorForm()
    try:
        if form.validate_on_submit():
            label = function.generator_password(form.lengthen.data, form.byword.data)
    except TypeError:
        flash('Число должно быть не меньше 6 и не больше 52')

    return render_template('generator.html', form=form, label=label)


@app.route('/change-password', methods=["GET", "POST"])
@function.login_required
def change_password(error=None):
    if error is None:
        error = request.args.get('error', '')
    form = forms.ChangeForm()
    if form.validate_on_submit():
        try:
            with sqlite3.connect('users.db') as conn:
                conn.row_factory = sqlite3.Row  # интерестная строчка которая нужна
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT 1 FROM passwords WHERE name = ? AND username = ? AND user_id = ?",
                    (form.name.data, form.username.data, session['user'])
                )
                if not cursor.fetchone():
                    return redirect(url_for('change_password', error="Неверный логин или пароль"))
                else:
                    encrypted_password = function.encrypt(form.changedpassword.data)
                    cursor.execute(
                        """UPDATE passwords SET password = ? WHERE name = ? AND username = ? AND user_id = ?""",
                        (encrypted_password, form.name.data, form.username.data, session['user']))
                    conn.commit()
                    flash('Пароль успешно изменён!', 'success')
                    return redirect(url_for('personal_main'))

        except Exception as e:
            conn.rollback()
            flash(f'Ошибка при изменении пароля: {str(e)}', 'danger')
            return redirect(url_for('change_password'))

    return render_template('change-password.html', form=form, error=error)


@app.route('/delete-password', methods=["GET", "POST"])
@function.login_required
def delete_password():
    if request.method == 'GET':
        name = request.args.get('name')
        username = request.args.get('username')
        mode = request.args.get('mode')
        if not name or not username:
            flash('Не указаны обязательные поля', 'error')
            return redirect(url_for('personal_main'))
        return render_template('delete-password.html', name=name, username=username, mode=mode)

    # Обработка POST-запроса
    name = request.form.get('name')
    username = request.form.get('username')
    mode = request.args.get('mode')

    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            if mode == "True":
                cursor.execute(
                    "DELETE FROM passwords WHERE name = ? AND username = ? AND user_id = ?",
                    (name, username, session['user'])
                )
                cursor.execute(
                    "DELETE FROM share WHERE name = ? AND username = ? AND sendername = ?",
                    (name, username, session['username'])
                )
            elif mode == "False":
                cursor.execute(
                    "DELETE FROM share WHERE name = ? AND username = ? AND ownername = ?",
                    (name, username, session['name']))
            conn.commit()
            flash('Пароль успешно удалён', 'success')
    except Exception as e:
        flash(f'Ошибка при удалении: {str(e)}', 'danger')

    return redirect(url_for('personal_main'))


@app.route('/add', methods=["GET", "POST"])
@function.login_required
def add(error=None):
    if error is None:
        error = request.args.get('error', '')
    form = forms.NoteForm()
    if form.validate_on_submit():
        data = function.encrypt(form.password.data)
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM passwords WHERE user_id = ? AND name = ? AND username = ? LIMIT 1)",
                (session['user'], form.name.data, form.username.data))
            exists = cursor.fetchone()[0]  # Берём первый элемент кортежа (0 или 1)

            if exists:
                return redirect(url_for("add", error="Такая запись уже есть", form=form))
            else:
                cursor.execute("INSERT INTO passwords (user_id, name, username, password) VALUES (?, ?, ?, ?)",
                               (session['user'], form.name.data, form.username.data, data))
                conn.commit()
                flash('Пароль добавлен!', 'success')
                return redirect(url_for('personal_main'))
    return render_template('add_note.html', form=form, error=error)


@app.route("/share-password", methods=["GET", "POST"])
@function.login_required
def share_password(error=None):
    error = request.args.get('error', '')
    form = forms.ShareForm()
    name = request.args.get('name')
    username = request.args.get('username')

    if not name or not username:
        return redirect(url_for('share-password', error='Не указаны обязательные поля'))

    if request.method == 'POST' and form.validate_on_submit():
        password = form.password.data
        recipient_username = form.recipient_username.data

        try:
            with sqlite3.connect("users.db") as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = ?", (recipient_username,))
                recipient = cursor.fetchone()
                if not recipient:
                    return redirect(url_for('share-password', error='Получатель не найден', name=name, username=username))
                cursor.execute("""
                    SELECT password FROM passwords 
                    WHERE user_id = ? 
                    AND name = ? 
                    AND username = ?""",
                    (session['user'], name, username))
                password_data = cursor.fetchone()

                if not password_data:
                    return redirect(url_for('share-password', error='Запись не найдена', name=name, username=username))
                decrypted_password = function.decrypt(password_data['password'])
                if decrypted_password != password:
                    flash('Неверный пароль', 'error')
                    return redirect(url_for('share_password', error='Неверный пароль', name=name, username=username))
                cursor.execute("""
                    SELECT 1 FROM share 
                    WHERE ownername = ? 
                    AND sendername = ? 
                    AND name = ? 
                    AND username = ?""",
                    (recipient['id'], session['username'], name, username))
                if cursor.fetchone():
                    return redirect(url_for('share_password', error='Вы уже делились этим паролем с данным пользователем', name=name, username=username))
                cursor.execute("""
                    INSERT INTO share (ownername, sendername, name, username, password) 
                    VALUES (?, ?, ?, ?, ?)""",
                    (recipient['id'], session['username'], name, username, password_data['password']))
                conn.commit()

                flash('Пароль успешно передан!', 'success')
                return redirect(url_for('personal_main'))

        except Exception as e:
            print(f"Error: {str(e)}")
            flash('Произошла ошибка при передаче пароля', 'error')
            return redirect(url_for('share_password', name=name, username=username))

    return render_template('share-password.html',
                         name=name,
                         username=username,
                         form=form,
                         error="")

@app.route("/view-password", methods=["GET", "POST"])
@function.login_required
def view_password():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sendername, name, username, password FROM share WHERE ownername = ?", (session["user"],))
        encrypted_notes = cursor.fetchall()

        notes = []
        for note in encrypted_notes:
            sender_name, name, username, encrypted_password = note
            try:
                decrypted_password = function.decrypt(encrypted_password)
            except:
                decrypted_password = "Ошибка расшифровки"
            notes.append((sender_name, name, username, decrypted_password))
    return render_template("view-password.html", notes=notes, username=session['username'])

@app.route('/main')
@function.login_required
def personal_main():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, username, password FROM passwords WHERE user_id = ?", (session["user"],))
        encrypted_notes = cursor.fetchall()

        notes = []
        for note in encrypted_notes:
            name, username, encrypted_password = note
            try:
                decrypted_password = function.decrypt(encrypted_password)
            except:
                decrypted_password = "Ошибка расшифровки"
            notes.append((name, username, decrypted_password))
    return render_template("main.html", notes=notes, username=session['username'])

init_db()
app.run(host="0.0.0.0", port=81)
