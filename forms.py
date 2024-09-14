from flask_wtf import FlaskForm
from wtforms import IntegerField, Label, StringField, PasswordField, SelectField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, DataRequired , Length
from models import Service, User

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
    user_id = StringField('User Id',validators=[DataRequired()])
    user_name = StringField('User Name',validators=[DataRequired()])
    service_type = SelectField('Service Type', choices=[], validators=[DataRequired()])
    experience = IntegerField('Experience (in years)', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Update Profile')

    def __init__(self, *args, **kwargs):
        super(ProfessionalProfileForm, self).__init__(*args, **kwargs)
        # Populate the choices dynamically from the database
        self.service_type.choices = [(service.id, service.name) for service in Service.query.all()]