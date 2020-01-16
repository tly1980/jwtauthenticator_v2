from setuptools import setup

setup(
    name='jupyterhub-jwtauthenticator-v2',
    version='2.0.1',
    description='JSONWebToken Authenticator for JupyterHub',
    url='https://github.com/izihawa/jwtauthenticator_v2',
    author='ppodolsky',
    author_email='ppodolsky@me.com',
    license='Apache 2.0',
    packages=['jwtauthenticator'],
    install_requires=[
        'jupyterhub',
        'pyjwt',
    ]
)
