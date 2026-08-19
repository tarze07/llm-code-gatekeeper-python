import fastapi_turbo_utils


def hello() -> str:
    return fastapi_turbo_utils.greet()
