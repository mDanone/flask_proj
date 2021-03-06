from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


class Permission:
	FOLLOW = 0x01
	COMMENT = 0x02
	WRITE_ARTICLES = 0x04
	MODERATE_COMMENTS = 0x08
	ADMINISTER = 0x80


class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	default = db.Column(db.Boolean, default=False, index=True)
	permission = db.Column(db.Integer)
	users = db.relationship('User', backref='role',lazy='dynamic')
	def __repr__(self):
		return '<Role {}>'.format(self.name)

	@staticmethod
	def insert_roles():
		roles = {
		'User': (Permission.FOLLOW | 
				 Permission.COMMENT |
				 Permission.WRITE_ARTICLES, True),
		'Moderator': (Permission.FOLLOW | 
				 	  Permission.COMMENT |
				 	  Permission.WRITE_ARTICLES |
				 	  Permission.MODERATE_COMMENTS, False),
		'Administrator': (0xff, False)
		}
		for r in roles:
			role = Role.query.filter_by(name=r).first()
			if role is None:
				role = Role(name=r)
			role.permission = roles[r][0]
			role.default = roles[r][1]
			db.session.add(role)
		db.session.commit()


class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	password_hash = db.Column(db.String(128))
	email = db.Column(db.String(64), unique=True, index=True)
	username = db.Column(db.String(64), unique=True, index=True)
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	confirmed = db.Column(db.Boolean, default=False)
	name = db.Column(db.String(64))
	location = db.Column(db.String(64))
	about_me = db.Column(db.Text())
	member_since = db.Column(db.DateTime(), default=datetime.utcnow)
	last_seen = db.Column(db.DateTime(), default=datetime.utcnow)


	def ping(self):
		self.last_seen = datetime.utcnow()
		db.session.add(self)


	def __init__(self, **kwargs):
		super(User, self).__init__(**kwargs)
		if self.role is None:
			if self.email == current_app.config['FLASKY_ADMIN']:
				self.role = Role.query.filter_by(permission=0xff).first()
			if self.email == current_app.config['FLASKY_MODER']:
				self.role = Role.query.filter_by(permission=0x0f).first()
			if self.role is None:
				self.role = Role.query.filter_by(default=True).first()


	def can(self, permissions):
		return self.role is not None and \
			(self.role.permission & permissions) == permissions


	def is_administrator(self):
		return self.can(Permission.ADMINISTER)


	def generate_confirmation_token(self, expiration=3600):
		 s = Serializer(current_app.config['SECRET_KEY'], expiration)
		 return s.dumps({'confirm': self.id})


	def confirm(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return False
		if data.get('confirm') != self.id:
			return False
		self.confirmed = True
		db.session.add(self)
		db.session.commit()
		return True


	def __repr__(self):
		return '<User> {}'.format(self.username)
	

	@property
	def password(self):
		raise AttributeError('password is not a readeble attribute')


	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)


	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)


	def generate_reset_token(self, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'reset': self.id}).decode('utf-8')

	@staticmethod
	def reset_password(token, new_password):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token.encode('utf-8'))
		except:
			return False
		user = User.query.get(data.get('reset'))
		if user is None:
			return False
		user.password = new_password
		db.session.add(user)
		return True


	def generate_change_email(self, new_email, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'change_email':self.id, 'new_email': new_email})


	def change_email(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token.encode('utf-8'))
		except:
			return False
		if data.get('change_email') != self.id:
			return False
		new_email = data.get('new_email')
		if new_email is None:
			return False
		if self.query.filter_by(email=new_email).first() is not None:
			return False
		self.email = new_email
		db.session.add(self)
		return True


class AnonymousUser(AnonymousUserMixin):
	def can(self, permissions):
		return False

	def is_administrator(self):
		return False


login_manager.anonymous_user = AnonymousUser