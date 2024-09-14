from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

app= Flask(__name__)

#database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY']='no one knows'

db= SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class LoginForm(FlaskForm):
    email= StringField('EMAIL', validators=[DataRequired()])
    password= PasswordField('PASSWORD', validators=[DataRequired()])
    submit=SubmitField('SUBMIT')

#login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=Users.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Successfull!!")
                return redirect(url_for('posts'))
            else:
                flash('Wrong Password - Please Tryagain')
        else:
            flash("You are not registered with us --Please SIGN IN")                 
    return render_template('login.html', form=form, title='LOGIN')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('YOU HAVE BEEN LOGGED OUT !!')
    return redirect(url_for('login'))

#dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form=LoginForm()
    return render_template('dashboard.html', form=form)





class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    #author = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, default=lambda: datetime.utcnow().replace(microsecond=0))
    slug=db.Column(db.String(200))

    #foreign key to link Users reference primary key

    post_id = db.Column(db.Integer, db.ForeignKey('users.id'))

@app.route('/posts')
def posts():

    posts=Posts.query.order_by(Posts.date_posted)

    return render_template('posts.html', posts=posts, title='POSTS')


#post form
class PostForm(FlaskForm):
    title=StringField('TITLE', validators=[DataRequired()])
    content=TextAreaField('CONTENT', validators=[DataRequired()])
    author=StringField('Author')
    slug=StringField('SLUG', validators=[DataRequired()])
    submit=SubmitField('SUBMIT')

@app.route('/add-post', methods=['GET', 'POST'])
def add_post():
    form=PostForm()

    if form.validate_on_submit():
        poster = current_user.id
        post=Posts(title=form.title.data, content=form.content.data, post_id=poster, slug=form.slug.data)
        #clear form
        form.title.data=''
        form.content.data=''
        form.author.data=''
        form.slug.data=''

        db.session.add(post)
        db.session.commit()

        flash('Post Submitted Successfully!!')

    return render_template('add_post.html', form=form, title='ADD POST')           


@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = Userform()

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User Deleted Successfully!!')

        our_users = Users.query.order_by(Users.date_added)
        return render_template('add_user.html', form=form, name=name, our_users=our_users,title='DELETE')
    

    except:
        flash('There was a problem -- Try again')
        return render_template('add_user.html', form=form, name=name, our_users=our_users, title='DELETE')
    

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(25), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    password_hash= db.Column(db.String(120))
    #One to many relationship

    posts = db.relationship('Posts', backref='poster')

    @property
    def password(self):
        raise AttributeError('password is not readble attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash=generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.name}>"

class Userform(FlaskForm):
    name=StringField('NAME', validators=[DataRequired()])
    username=StringField('USERNAME', validators=[DataRequired()])
    email=StringField('EMAIL', validators=[DataRequired()])
    password_hash = PasswordField('PASSWORD', validators=[DataRequired(), EqualTo('confirm_password', message='Passwords Must Match')])
    confirm_password = PasswordField('CONFIRM PASSWORD', validators=[DataRequired()])
    submit=SubmitField('SUBMIT')
    

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = Userform()
    name_to_update = Users.query.get_or_404(id)

    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']

        try:
            db.session.commit()  # Try to commit changes
            flash('User Updated Successfully!')
            return render_template('update.html', form=form, name_to_update=name_to_update, title='UPDATE')
        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            flash(f'Error: There was a problem updating the user. {str(e)}')
            return render_template('update.html', form=form, name_to_update=name_to_update)
    else:
        return render_template('update.html', form=form, name_to_update=name_to_update, id=id, title='UPDATE')


class Passwordform(FlaskForm):
    email=StringField('EMAIL', validators=[DataRequired()])
    password_hash=PasswordField('PASSWORD', validators=[DataRequired()])
    submit=SubmitField('SUBMIT')

#Form class
class Namerform(FlaskForm):
    name=StringField('Name', validators=[DataRequired()])
    submit=SubmitField('Submit')

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = Userform()
    if form.validate_on_submit():
        user=Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_PW = generate_password_hash(form.password_hash.data)
            user = Users(username=form.username.data,name=form.name.data, email=form.email.data, password_hash= hashed_PW)
            db.session.add(user)
            db.session.commit()
            flash('User Added Successfully!')
            return redirect(url_for('login'))

        name = form.name.data
        form.name.data = ''
        form.username.data=''
        form.email.data = ''
        form.password_hash.data = ''
        
    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html', form=form, name=name, our_users=our_users, title='REGISTER')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=name, title='PROFILE')

#Error Pages
#Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("404.html"), 500

#password page
@app.route('/test_PW', methods=['GET', 'POST'])
def test_PW():
    email=None
    password=None
    pw_to_check=None
    passed=None

    form= Passwordform()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        #Clear form
        form.email.data=''
        form.password_hash.data=''

        pw_to_check = Users.query.filter_by(email=email).first()

        passed = check_password_hash(pw_to_check.password_hash, password)
        
    return render_template("testpwd.html", email=email, password=password, form = form, pw_to_check=pw_to_check, passed = passed)


#Name page
@app.route('/name', methods=['GET', 'POST'])
def name():
    name=None
    form=Namerform()
    if form.validate_on_submit():
        name=form.name.data
        form.name.data=''
        flash('Submitted Successfully')

    return render_template("name.html", name=name, form=form, title='NAME')

@app.route('/about')
def about_us():
    return render_template('about.html', title='ABOUT US')

if __name__ == '__main__':
    app.run(debug=True)