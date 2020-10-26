from flask import render_template, redirect, request, url_for, flash
from . import auth
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm
from ..email import send_email
from .. import db


@auth.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if current_user.is_authenticated:
		return redirect(url_for('main.index'))
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(url_for('main.index'))
		flash('invalid username or password')
	return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
	logout_user()
	flash("You've been succesfully logged out")
	return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data,
					username = form.username.data,
					password = form.password.data,)
		db.session.add(user)
		db.session.commit()
		token = user.generate_confirmation_token()
		send_email(user.email, 'Confirm Your Account',
							'auth/email/confirm', user=user,
							 token=token)
		flash('A confirmation email has been sent to you by email.')
		return redirect(url_for('auth.login'))
	return render_template('auth/register.html',
							form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
	if current_user.confirmed:
		return redirect(url_for('main.index'))
	if current_user.confirm(token):
		flash('you have been confirmed your account. Thanks!')
	else:
		flash('The confirmation link is invalid or has expired. ')
	return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
	if current_user.is_authenticated:
		current_user.ping()
		if not current_user.confirmed \
				and request.endpoint[:5] != 'auth.':
			return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
	if current_user.is_anonymous or current_user.confirmed:
		return redirect(url_for('main.index'))
	return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
	token = current_user.generate_confirmation_token()
	send_email(current_user.email, 'Confirm Your Account', 'auth/email/confirm',user=current_user, token=token)
	flash('A new confirmation email has been sent to you by email')
	return redirect(url_for('main.index'))


@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
	form = ChangePasswordForm()
	if form.validate_on_submit():
		if current_user.verify_password(form.old_password.data):
			current_user.password = form.change_password.data
			db.session.add(current_user)
			db.session.commit()
			flash('The password was changed')
			return redirect(url_for('main.index'))
		else:
			flash('invalid password')
	return render_template("auth/change_password.html", form=form)

@auth.route('/reset_request', methods=['GET', 'POST'])
def password_reset_request():
	if not current_user.is_anonymous:
		return redirect(url_for('main_index'))
	form = PasswordResetRequestForm()
	user = User.query.filter_by(email=form.email.data).first()
	if form.validate_on_submit():
		if user:
			token = user.generate_reset_token()
			send_email(user.email, 'Confirm Your Account',
							'auth/email/reset_confirmation',
							 user=user, token=token)
			flash('An email with instructions to reset your password has been '
				'sent to you.')
		else:
			flash('This email is not registered')
		return redirect(url_for('auth.login'))
	return render_template('auth/reset_request.html', form=form)

@auth.route('/reset/<token>', methods=['GET', 'POST'])
def reset_confirm(token):
	if not current_user.is_anonymous:
		return redirect(url_for('main.index'))
	form = PasswordResetForm()
	if form.validate_on_submit():
		if User.reset_password(token,form.new_password.data):
			db.session.commit()
			flash('Your password has been updated.')
			return redirect(url_for('auth.login'))
		else:
			return redirect(url_for('main.index'))
	return render_template('auth/reset.html', form=form)


@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email_request():
	if current_user.is_anonymous:
		return redirect(url_for('main_index'))
	form = ChangeEmailForm()
	user = User.query.filter_by(email=current_user.email).first()
	if form.validate_on_submit():
		if form.email.data != current_user.email:
			token = user.generate_change_email(form.email.data)
			send_email(form.email.data, 'Change your email',
							'auth/email/email_changer',
							 user=user, token=token)
			flash('the email sent to your mail')
	return render_template('auth/change_email.html', form=form)

@auth.route('/email_change/<token>', methods=['GET', 'POST'])
def change_email_confirmed(token):
	if current_user.is_anonymous:
		return redirect(url_for('main.index'))
	user = User.query.filter_by(email=current_user.email).first()
	if user.change_email(token):
		db.session.commit()
		flash('Your email address has been updated.')
	else:
		flash('Invalid request.')
	return redirect(url_for('main.index'))
