from app import db
from flask_login import UserMixin

class Account(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email_address = db.Column(db.String(40), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f"<Account {self.username}>"

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    reservation_date = db.Column(db.String(10), nullable=False)
    reservation_time = db.Column(db.String(5), nullable=False)
    details = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<Reservation {self.reservation_date} {self.reservation_time}>"
