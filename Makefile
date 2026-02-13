run:
    python -m src.cli --input src/sample.log

test:
    python -m pytest

clean:
    powershell -Command "Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force"
