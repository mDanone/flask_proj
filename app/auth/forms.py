from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
	email = StringField('Write your Email', validators=[DataRequired(),
														Length(1,64),
														Email(),])
	password = PasswordField('password', validators=[DataRequired()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log in')


class RegistrationForm(FlaskForm):
	email = StringField('Write your Email', validators=[DataRequired(),
														Length(1,64),
														Email(),])
	username = StringField('Username', validators=[
		DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
										'Username must have only letters, '
										'numbers, dots or underscores')])
	password = PasswordField('Password', validators=[
		DataRequired(), EqualTo('password2', message='Password must match')])
	password2 = PasswordField('Confirm password', validators=[DataRequired()])
	submit = SubmitField('Register')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already in use.')

class ChangePasswordForm(FlaskForm):
	old_password = PasswordField('Old password', validators=[DataRequired()])
	change_password = PasswordField('Password', validators=[
		DataRequired(), EqualTo('change_password2', message='Password must match')])
	change_password2 = PasswordField('Confirm changing', validators=[DataRequired()])
	submit = SubmitField('Change password')


class PasswordResetRequestForm(FlaskForm):
	email = StringField('Write your Email', validators=[DataRequired(),
														Length(1,64),
														Email(),])
	submit = SubmitField('Reset Password')

class PasswordResetForm(FlaskForm):
	new_password = PasswordField('Write new password', validators=[DataRequired(),
														EqualTo('new_password2', message='Password must match')])
	new_password2 = PasswordField('Confirm your new password', validators=[DataRequired()])
	submit = SubmitField('Submit')

class ChangeEmailForm(FlaskForm):
	email = StringField('Write your Email to change', validators=[DataRequired(),
														Length(1,64),
														Email(),])
	submit = SubmitField('Reset Password')