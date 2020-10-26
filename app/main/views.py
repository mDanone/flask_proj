from flask import render_template, session, redirect, url_for, abort
from . import main
from .forms import NameForm
from .. import db
from ..models import User, Role, Permission
from manage import app
from ..decorators import admin_required, permission_required
from flask_login import login_required


@main.route('/', methods=['GET', 'POST'])
def index():
	return render_template('index.html', name=session.get('name'),
		known=session.get('known', False))


@main.route('/admin')
@login_required
@admin_required
def for_admins_only():
	return "For Administrators"


@main.route('/moderator')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def for_moderators_only():
	return "For comment moderators!"


@main.app_context_processor
def inject_permission():
	return dict(Permission=Permission)

@main.route('/user/<username>')
def user(username):
	with db.session.no_autoflush:
		user = User.query.filter_by(username=username).first()
	if user is None:
		abort(404)
	return render_template('user.html', user=user)