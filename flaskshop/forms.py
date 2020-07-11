from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, DecimalField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from flaskshop.models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')


class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


class ProductForm(FlaskForm):
    name = StringField("Product Name", validators=[DataRequired()])
    price = DecimalField('Price', validators=[NumberRange(min=1, max=9999), DataRequired()], default=0)
    qty = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=0, max=9999)], default=0)
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])

    submit = SubmitField("List Product")


class CheckoutForm(FlaskForm):
    firstName = StringField('First Name', validators=[DataRequired()], render_kw={"placeholder": "John"})
    lastName = StringField('Last Name', validators=[DataRequired()], render_kw={"placeholder": "Doe"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"placeholder": "johndoe@gmail.com"})
    address = StringField('Address', validators=[DataRequired()], render_kw={"placeholder": "180 Ang Mo Kio Ave 8"})
    postal = StringField('Postal Code', validators=[DataRequired()], render_kw={"placeholder": "569830"})
    cardName = StringField('Name on Card', validators=[DataRequired()], render_kw={"placeholder": "John Doe"})
    cardNumber = StringField('Card Number', validators=[DataRequired()], render_kw={"placeholder": "1111-2222-3333-4444"})
    expDate = StringField('Exp Month', validators=[DataRequired()], render_kw={"placeholder": "Apr/25"})
    cvv = IntegerField('CVV', validators=[DataRequired()], render_kw={"placeholder": "123"})


class SearchForm(FlaskForm):
    search = StringField('search')
    submit = SubmitField("Seach", render_kw={'class': 'btn btn-success btn-block'})


class ContactUsForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])

    submit = SubmitField("Submit")