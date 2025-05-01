import random
from flask import Flask, flash, render_template, redirect, url_for, session, request, abort
import sqlite3
from init import init_db
import function
import forms

app = Flask(__name__)
app.config['SECRET_KEY'] = 'veryverystrongkeypassword'


@app.route('/')
def slash():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
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
            flash('Этот логин занят', 'danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
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
            # flash('Вы успешно вошли!', 'success')
            return redirect(url_for('personal_main', user=user[0]))
        else:
            flash('Непавильный логин или пароль', 'danger')
    return render_template('login.html', form=form)


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
def change_password():
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
                    flash('Запись не найдена', 'error')
                else:
                    encrypted_password = function.encrypt(form.changedpassword.data)
                    cursor.execute("""UPDATE passwords SET password = ? WHERE name = ? AND username = ? AND user_id = ?""",
                                   (encrypted_password, form.name.data, form.username.data, session['user']))
                    conn.commit()
                    flash('Пароль успешно изменён!', 'success')
                    return redirect(url_for('personal_main', user=session['user']))

        except Exception as e:
            conn.rollback()
            flash(f'Ошибка при изменении пароля: {str(e)}', 'danger')
            return redirect(url_for('change_password'))

    return render_template('change-password.html', form=form)


@app.route('/delete-password', methods=["GET", "POST"])
@function.login_required
def delete_password():
    form = forms.DeleteForm()
    if form.validate_on_submit():
        try:
            with sqlite3.connect('users.db') as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT 1 FROM passwords WHERE name = ? AND username = ? AND user_id = ?",
                    (form.name.data, form.username.data, session['user'])
                )
                if not cursor.fetchone():
                    flash('Запись не найдена', 'error')
                else:
                    cursor.execute(
                        "DELETE FROM passwords WHERE name = ? AND username = ? AND user_id = ?",
                        (form.name.data, form.username.data, session['user'])
                    )
                    conn.commit()
                    flash('Пароль успешно удалён', 'success')
                    return redirect(url_for('personal_main', user=session['user']))
        except:
            print('hello world')
            flash('Я РАБОТАЮ В 3 ЧАСА НОЧИ УЖЕ ЧАСОВ 5')
    return render_template('delete-password.html', form=form)


@app.route('/add', methods=["GET", "POST"])
@function.login_required
def add():
    form = forms.NoteForm()
    # TODO: добавить генерацию пароля на страницу с добавлением пароля
    # password = function.generator_password()
    # form.password.data = password
    if form.validate_on_submit():
        data = function.encrypt(form.password.data)
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM passwords WHERE user_id = ? AND name = ? AND username = ? LIMIT 1)",
                (session['user'], form.name.data, form.username.data))
            exists = cursor.fetchone()[0]  # Берём первый элемент кортежа (0 или 1)

            if exists:
                flash('Это уже есть', 'danger')
            else:
                cursor.execute("INSERT INTO passwords (user_id, name, username, password) VALUES (?, ?, ?, ?)",
                               (session['user'], form.name.data, form.username.data, data))
                conn.commit()
                flash('Пароль добавлен!', 'success')
                return redirect(url_for('personal_main', user=session['user']))
    return render_template('add_note.html', form=form)


@app.route('/main')
@function.login_required
def redirect_to_personal():
    return redirect(url_for('personal_main', user=session['user']))


@app.route('/main/<int:user>', methods=["GET"])
@function.login_required
def personal_main(user):
    if user != session['user']:
        abort(403)
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user,))
        user_data = cursor.fetchone()
        if not user_data:
            abort(404)

        cursor.execute("SELECT name, username, password FROM passwords WHERE user_id = ?", (user,))
        encrypted_notes = cursor.fetchall()

        notes = []
        for note in encrypted_notes:
            name, username, encrypted_password = note
            try:
                decrypted_password = function.decrypt(encrypted_password)
            except:
                decrypted_password = "Ошибка расшифровки"
            notes.append((name, username, decrypted_password))

    return render_template("main.html", username=session['username'], notes=notes)


init_db()
app.run(host="0.0.0.0", port=81)
