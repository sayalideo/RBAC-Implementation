from rbac import db, login_manager
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    roles = db.relationship('Role', secondary='user_roles')

    def __repr__(self):
        return f"User('{self.username}')"

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


# Define the Role data-model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True) 

# Define the UserRoles association table
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(200), unique=True, nullable=False)
    event_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default=False) #0=not approved; 1=approved; 2=done

class Fund(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer)
    description = db.Column(db.String(200), nullable=False)
    event_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False) #0=not approved; 1=approved;

class Advertisement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    college_list = db.relationship('College', backref='advertisement', lazy=True)
    status = db.Column(db.String(20), nullable=False) #0=not approved; 1=approved;

class College(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True) 
    advt_id = db.Column(db.Integer, db.ForeignKey('advertisement.id'), nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False) #0=not approved; 1=approved;