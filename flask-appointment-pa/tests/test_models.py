from app.models import Account

def test_account_repr():
    acc = Account(username="user", email_address="u@test.com", hashed_password="hash")
    assert "user" in repr(acc)
