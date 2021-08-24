from setuptools import setup

setup(
    url="https://github.com/trussworks/logindotgov-oidc-py",
    python_requires=">3.5",
    name="logindotgov-oidc",
    packages=["logindotgov"],
    version="0.1.0",
    description="OpenID Connect Relying Party client",
    author="Peter Karman",
    author_email="peter@truss.works",
    license="MIT",
    install_requires=[],
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    test_suite="tests",
)
