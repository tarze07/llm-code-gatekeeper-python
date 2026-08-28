from app import price_with_discount


def test_price_with_discount():
    assert price_with_discount(100) == 123.0
