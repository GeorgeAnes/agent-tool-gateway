PY ?= python
test: ; $(PY) -m pytest -q
demo: ; $(PY) app.py
matrix: ; $(PY) -m toolgate.attacks
bench: ; $(PY) bench.py
