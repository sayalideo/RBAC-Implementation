from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from rbac.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username = username.data).first()
        if user:
            raise ValidationError('Username Already Exists! Please try another one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')

class AddRoleForm(FlaskForm):
    name = StringField('Role', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField('Add Role')

class ReportForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=2, max=200)])
    submit = SubmitField('Submit Report')

class FundForm(FlaskForm):
    amount = IntegerField('Amount')
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=2, max=200)])
    submit = SubmitField('Add Fund')

class AdvtForm(FlaskForm):
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=2, max=200)])
    submit = SubmitField('Add Advertisement')

class EventForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=2, max=200)])
    submit = SubmitField('Add Event')