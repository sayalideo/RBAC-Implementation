from flask import render_template, flash, redirect, url_for, request
from rbac import app, db, bcrypt
from rbac.forms import RegistrationForm, LoginForm, AddRoleForm
from rbac.models import User, Role, UserRoles
from flask_login import login_user, current_user, logout_user, login_required

def get_role(user):
    i = 0
    for role in user.roles:
        if role.name == 'Admin':
            role = 'Admin'
            break
        elif role.name == 'CP':
            role = 'CP'
            break
        elif role.name == 'EH':
            role = 'ET'
            break
        elif role.name == 'PRH':
            role = 'PRH'
            break
        elif role.name == 'TR':
            role = 'TR'
            break
        elif role.name == 'DH':
            role = 'DH'
            break
        elif role.name == 'ET':
            role = 'ET'
            for j in range(i+1,len(user.roles)):
                if user.roles[j].name == 'EH':
                    role = 'EH'
                    break
        elif role.name == 'PRT':
            role = 'PRT'
            for j in range(i+1,len(user.roles)):
                if user.roles[j].name == 'PRH':
                    role = 'PRH'
                    break
        else:
            role = 'NM'
        i = i + 1
    return role


@app.route("/")
def home():
    role =''
    if current_user.is_authenticated:
        role = get_role(current_user)
    return render_template('home.html',role=role)

@app.route("/register", methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username = form.username.data, password=hashed_password)
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

def get_user_by_role():
    users = User.query.all()
    admin,cp,dh,eh,prh,tr,prt,et,nm = [],[],[],[],[],[],[],[],[]
    for user in users:
        role = get_role(user)
        if role == 'Admin':
            cp.append(user)
        elif role == 'CP':
            vcp.append(user)
        elif role == 'DH':
            dh.append(user)
        elif role == 'EH':
            eh.append(user)
        elif role == 'PRH':
            prh.append(user)
        elif role == 'TR':
            tr.append(user)
        elif role == 'PRT':
            prt.append(user)
        elif role == 'ET':
            et.append(user)
        else:
            nm.append(user)
    return admin,cp,dh,eh,prh,tr,prt,et,nm

@app.route("/admin")
@login_required
def admin():
    if get_role(current_user) != 'Admin':
        return redirect(url_for('home'))
    admin,cp,dh,eh,prh,tr,prt,et,nm = get_user_by_role()
    return render_template('admin.html',admin=admin,cp=cp,dh=dh,eh=eh,prh=prh,tr=tr,prt=prt,et=et,nm=nm)

@app.route("/cp_dashboard")
@login_required
def cp_dashboard():
    if get_role(current_user) != 'CP':
        return redirect(url_for('home'))
    return render_template('cp_dashboard.html')

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
    return render_template('all_roles.html',form=form,roles=roles)

@app.route("/delete_role/<rid>")
@login_required
def delete_role(rid):
    r = Role.query.get(rid)
    db.session.delete(r)
    db.session.commit()
    return redirect(url_for('all_roles'))

@app.route("/delete_userrole/<rid>/<uid>")
@login_required
def delete_userrole(rid,uid):
    u = User.query.get(uid)
    r = Role.query.get(rid)
    u.roles.remove(r)
    db.session.add(u)
    db.session.commit()
    return redirect(url_for('add_roles',id=uid))

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
    
    allroles = []
    allr = Role.query.all()
    for role in allr:
        allroles.append(role.name)
    return render_template('add_roles.html',form=form,u=u,roles=u.roles,allroles = allroles)