"""Fixture testowy reguł „nigdy".

Adnotacja przed linią oznacza oczekiwanie: pierwsza rodzina mówi „tu reguła
MUSI trafić", druga „tu NIE wolno jej trafić". Test negatywny jest równie ważny
jak pozytywny: reguła blokująca poprawny kod kosztuje zaufanie do całej bramy.

Uruchomienie: semgrep --test --config rules/semgrep rules/semgrep/tests
"""

import os
import pickle
import ssl
import subprocess

import requests
import yaml


def tls(url, dane):
    # ruleid: no-tls-verify-disabled
    requests.get(url, verify=False)
    # ruleid: no-tls-verify-disabled
    ssl._create_unverified_context()
    # ok: no-tls-verify-disabled
    requests.get(url, verify=True)
    # ok: no-tls-verify-disabled
    requests.get(url, timeout=5)


def dynamiczne(wejscie):
    # ruleid: no-eval-on-input
    eval(wejscie)
    # ok: no-eval-on-input
    eval("2 + 2")
    # ok: no-eval-on-input
    int(wejscie)


def sql(cursor, user_id):
    # ruleid: no-sql-string-concat
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # ruleid: no-sql-string-concat
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    # ok: no-sql-string-concat
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def polecenia(nazwa_pliku):
    # ruleid: no-shell-true
    subprocess.run(f"cat {nazwa_pliku}", shell=True)
    # ruleid: no-shell-true
    os.system("rm " + nazwa_pliku)
    # ok: no-shell-true
    subprocess.run(["cat", nazwa_pliku], check=True)
    # ok: no-shell-true
    subprocess.run("ls -la", shell=True)


def deserializacja(dane):
    # ruleid: no-unsafe-deserialization
    pickle.loads(dane)
    # ruleid: no-unsafe-deserialization
    yaml.load(dane)
    # ok: no-unsafe-deserialization
    yaml.safe_load(dane)


def nasluch(app, sock):
    # ruleid: no-hardcoded-bind-all-interfaces
    app.run(host="0.0.0.0", port=8000)
    # ok: no-hardcoded-bind-all-interfaces
    app.run(host="127.0.0.1", port=8000)
