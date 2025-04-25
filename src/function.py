import hashlib
import json
import random
import sqlite3
from functools import wraps
import base64
from flask import Flask, session, flash, redirect, url_for
import base64

# кодирование пароля
def encrypt(text):
    return base64.b64encode(text.encode()).decode()
# декодирование пароле
def decrypt(encrypted_text):
    return base64.b64decode(encrypted_text.encode()).decode()

# генератор паролей
def generator_password(lenght, myword):
    if len(myword) != 0:
        word = myword.split()
    else:
        with open('../words.json', 'r', encoding='utf-8') as f:
            word = json.load(f)
    num = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
    chtk = ["&", "#", "%", "$", "@"]
    password = ["num", "chtk", "word"]

    a = []
    b = 0
    c = ""
    d = False
    e = False

    while e is False:
        while d is False:
            while len(a) < (lenght // 2):
                a.append(random.choice(password))
                b = b + 1
            if ("num" in a and "word" in a and "chtk" in a) and (a[0] == "word"):
                d = True
            else:
                a = []
                b = 0

        for i in a:
            if i == "num":
                c = c + random.choice(num)
            elif i == "word":
                c = c + random.choice(word)
            else:
                c = c + random.choice(chtk)

        if len(c) == lenght:
            e = True
        else:
            c = ""

    return c

# проверка если в сессии пользователь (через фласк весь код переделовать)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:  # Проверяем session['user'] вместо session['user_id']
            flash('Пожалуйста, войдите в систему', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# хэширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()