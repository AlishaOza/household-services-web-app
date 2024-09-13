from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, PasswordField, SelectField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, DataRequired , Length

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=5, max=80)])
    role = SelectField('Role', choices=[('customer', 'Customer'), ('professional', 'Service Professional'), ('admin', 'Admin')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')

class ServiceForm(FlaskForm):
    name = StringField('Service Name', validators=[DataRequired()])
    price = IntegerField('Price', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ProfessionalProfileForm(FlaskForm):
    user_id = StringField('User Id', validators=[DataRequired()])
    service_type = StringField('Service Type', validators=[DataRequired()])
    experience = IntegerField('Experience (in years)', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Update Profile')

