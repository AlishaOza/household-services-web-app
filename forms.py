from flask_wtf import FlaskForm
from wtforms import DecimalField, FileField, FloatField, IntegerField, Label, StringField, PasswordField, SelectField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, DataRequired, Length, NumberRange
from flask_wtf.file import FileRequired, FileAllowed
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
    service_type = SelectField('Service Type', choices=[('haircut', 'Hair Cut'), ('cleaning', 'Cleaning Services'), ('electrical', 'Electrical Services'),('painting', 'Painting Services'),('plumbing', 'Plumbing Services')])
    name = StringField('Service Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ProfessionalProfileForm(FlaskForm):
    user_id = StringField('User Id',validators=[DataRequired()])
    user_name = StringField('User Name',validators=[DataRequired()])
    full_name = StringField('Full Name',validators=[DataRequired()])
    service_type = SelectField('Service Type', choices=[], validators=[DataRequired()])
    file = FileField('Upload File', validators=[FileRequired(),FileAllowed(['jpg', 'png', 'pdf', 'jpeg', 'gif'], 'Images and PDFs only!')])
    experience = IntegerField('Experience (in years)', validators=[DataRequired()])
    address = TextAreaField('Address', validators=[DataRequired()])
    pin_code = IntegerField('Pin Code', validators=[DataRequired()])
    
    submit = SubmitField('Update Profile')

    def __init__(self, *args, **kwargs):
        super(ProfessionalProfileForm, self).__init__(*args, **kwargs)
        # Populate the choices dynamically from the database
        self.service_type.choices = [(service.id, service.name) for service in Service.query.all()]

class CustomerProfileForm(FlaskForm):
    user_id = StringField('User Id',validators=[DataRequired()])
    user_name = StringField('User Name(e-mail)',validators=[DataRequired()])
    full_name = StringField('Full Name',validators=[DataRequired()])
    address = TextAreaField('Address', validators=[DataRequired()])
    pin_code = IntegerField('Pin Code', validators=[DataRequired()])
    submit = SubmitField('Update Customer Profile')

class ServiceRemarksForm(FlaskForm):
    request_id = StringField('Request Id',validators=[DataRequired()])
    service_name = StringField('Service Name',validators=[DataRequired()])
    service_description = StringField('Service Description',validators=[DataRequired()])
    full_name = StringField('User Name',validators=[DataRequired()])
    rating = FloatField('Rating', validators=[NumberRange(min=0, max=5, message="Rating must be between 0 and 5.")])
    remarks = TextAreaField('Remarks', validators=[DataRequired()])
    submit = SubmitField('Submit Remarks')