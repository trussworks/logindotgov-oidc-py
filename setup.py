from setuptools import find_packages, setup
setup(
    name='logindotgov-oidc',
    packages=find_packages(include=['logindotgov.oidc']),
    version='0.1.0',
    description='OpenID Connect Relying Party client',
    author='Peter Karman peter@truss.works',
    license='MIT',
    install_requires=[],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    test_suite='tests',
)

