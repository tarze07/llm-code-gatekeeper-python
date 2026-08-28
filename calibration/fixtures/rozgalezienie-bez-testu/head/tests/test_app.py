from app import classify


def test_classify_non_negative():
    assert classify(5) == "non-negative"
