from flask import render_template, flash, redirect, url_for, request
from rbac import app, db, bcrypt
from rbac.forms import RegistrationForm, LoginForm, AddRoleForm
from rbac.models import User, Role, UserRoles
from flask_login import login_user, current_user, logout_user, login_required



@app.route("/")
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username = form.username.data, password=hashed_password)
        r = Role.query.filter_by(name='NM').first()
        user.roles.append(r)
        db.session.add(user)
        db.session.commit()
        name = form.username.data
        s    = 'Account created for ' + name + ' successfully !'
        flash(s,'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, title='Register')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember= form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password.','danger')
    return render_template('login.html', form=form, title='Login')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/admin")
@login_required
def admin():
    roles = current_user.roles
    flag = 0
    for r in roles:
        if 'CP' == r.name:
            flag = 1
            break
    if flag == 0:
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin.html',users=users)

@app.route("/all_roles", methods=['GET', 'POST'])
@login_required
def all_roles():
    form = AddRoleForm()
    roles = Role.query.all()
    if form.validate_on_submit():
        r = Role(name=form.name.data)
        db.session.add(r)
        db.session.commit()
        return redirect(url_for('all_roles'))   
    return render_template('all_roles.html',roles=roles)

@app.route("/delete_role/<id>", methods=['POST'])
@login_required
def delete_roles(id):
    r = Role.query.get(id)
    db.session.delete(r)
    db.session.commit()
    return redirect(url_for('all_routes'))

@app.route("/add_roles/<id>", methods=['GET','POST'])
@login_required
def add_roles(id):
    form = AddRoleForm()
    u = User.query.get(id)
    if form.validate_on_submit():
        r = Role.query.filter_by(name=form.name.data).first()
        if r:
            u.roles.append(r)
            db.session.add(u)
            db.session.commit()
        return redirect(url_for('add_roles',id=id))
    
    roles = []
    for role in u.roles:
        roles.append(role.name)
    return render_template('add_roles.html',form=form,u=u,roles=roles)