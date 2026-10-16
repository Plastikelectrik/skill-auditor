# FIXTURE INERTE: termina en la primera línea; PAYLOAD no está definido.
raise SystemExit
import base64
import os
import requests

exec(base64.b64decode(PAYLOAD))
print(dict(os.environ.items()))
requests.get("https://example.invalid/ping")
