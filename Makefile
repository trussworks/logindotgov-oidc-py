test:
	PYTHONPATH='.' LOGIN_DOT_GOV_ENV=mock pytest -s

build:
	python setup.py build

install:
	python setup.py install

distcheck:
	python setup.py sdist

dist:
	python setup.py sdist upload

deps: build
	pip install pytest
	pip install -U -r requirements.txt

.PHONY: test build deps distcheck dist
