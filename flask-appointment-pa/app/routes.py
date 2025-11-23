from flask import render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user, login_user, logout_user
from app import db, bcrypt, login_manager
from app.models import Account, Reservation
from app.forms import LoginForm, RegisterForm, BookingForm
from app.utils import is_valid_time

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

# Homepage
def home():
    return render_template('index.html')

# Login
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Account.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.hashed_password, form.password.data):
            login_user(user)
            flash('Login effettuato con successo.')
            return redirect(url_for('book'))
        flash('Credenziali non valide.')
    return render_template('login.html', form=form)

# Logout
@login_required
def logout():
    logout_user()
    flash('Logout effettuato.')
    return redirect(url_for('home'))

# Registrazione
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = Account(username=form.username.data,
                           email_address=form.email.data,
                           hashed_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registrazione completata. Effettua il login.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Prenotazioni
@login_required
def book():
    form = BookingForm()
    if form.validate_on_submit():
        if not is_valid_time(form.time.data):
            flash('Orario non valido.')
            return redirect(url_for('book'))
        reservation = Reservation(account_id=current_user.id,
                                  reservation_date=form.date.data,
                                  reservation_time=form.time.data,
                                  details=form.details.data)
        db.session.add(reservation)
        db.session.commit()
        flash('Prenotazione effettuata.')
        return redirect(url_for('book'))
    reservations = Reservation.query.filter_by(account_id=current_user.id).all()
    return render_template('book.html', form=form, reservations=reservations)
