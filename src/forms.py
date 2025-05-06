from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange

class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class NoteForm(FlaskForm):
    name = StringField('Название сервиса', validators=[DataRequired()])
    username = StringField('Логин', validators=[DataRequired()])
    password = StringField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Добавить', validators=[DataRequired()])

class GeneratorForm(FlaskForm):
    lengthen = IntegerField('Длина Пароля', validators=[DataRequired(), NumberRange(min=6, max=52)])
    byword = StringField('Свои слова (Опционально)')
    submit = SubmitField('Сгенерировать')

class ChangeForm(FlaskForm):
    name = StringField('Название сервиса')
    username = StringField('Логин')
    changedpassword = StringField('Новый пароль')
    submit = SubmitField('Поменять')

class DeleteForm(FlaskForm):
    name = StringField('Назвавние сервиса')
    username = StringField("Логин")
    submit = SubmitField('Удалить')

class ShareForm(FlaskForm):
    recipient_username = StringField("Логин получателя")
    password = StringField("Подтвердите пароль")
    submit = SubmitField("Поделиться")

