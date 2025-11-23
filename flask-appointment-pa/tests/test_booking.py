from app import create_app, db
from app.models import Reservation, Account

def test_booking_creation(app):
    with app.app_context():
        user = Account(username="test", email_address="test@test.com", hashed_password="hash")
        db.session.add(user)
        db.session.commit()
        res = Reservation(account_id=user.id, reservation_date="2025-11-23", reservation_time="10:00", details="Test")
        db.session.add(res)
        db.session.commit()
        assert Reservation.query.count() == 1
