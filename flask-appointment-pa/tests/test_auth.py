import pytest
from app import create_app, db
from app.models import Account

@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI="sqlite:///:memory:")
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

def test_register_login(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password',
        'confirm_password': 'password'
    })
    assert b'Registrazione completata' in response.data
