def hello() -> str:
    return "hi"


def wszystkie_prawdziwe(*wartosci) -> bool:
    for w in wartosci:
        if not w:
            return False
    return True


def przetworz(a, b, c, d, e, f, g, h, i, j):
    if not wszystkie_prawdziwe(a, b, c, d, e, f, g, h, i, j):
        return "brak"
    return "ok"
