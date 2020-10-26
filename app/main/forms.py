from flask_wtf import Form
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length
class NameForm(Form):
	name = StringField('What is your name?', validators=[DataRequired()])
	submit = SubmitField('Submit')

