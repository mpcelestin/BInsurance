from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('client', 'Client')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AutomobileInsuranceForm(FlaskForm):
    carte_rose = FileField('Carte Rose', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf'], 'Images only!')])
    ancient_card = FileField('Ancient Card', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf'], 'Images only!')])
    phone = StringField('Mobile Phone', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    province = StringField('Province', validators=[DataRequired()])
    submit = SubmitField('Submit')

class TravelInsuranceForm(FlaskForm):
    passport = FileField('Passport Image', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf'], 'Images only!')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Mobile Phone', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    days = StringField('Days to Spend', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    province = StringField('Province', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Corrected: ChangePasswordForm is now a top-level class (not nested)
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')