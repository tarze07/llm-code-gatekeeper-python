def add(a: int, b: int) -> int:
    return a + b


def handle(request):
    return eval(request.get("expr"))
