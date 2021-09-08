test:
	PYTHONPATH='.' LOGIN_DOT_GOV_ENV=mock coverage run --source=logindotgov -m pytest -s -vv
	coverage report -m --skip-covered --fail-under 90

build:
	python setup.py build

install:
	python setup.py install

lint:
	flake8 logindotgov

lint-fix:
	black logindotgov

distcheck: lint
	python setup.py sdist

dist:
	python setup.py sdist upload

deps: build
	pip install pytest coverage
	pip install -U -r requirements.txt

.PHONY: test build deps distcheck dist
