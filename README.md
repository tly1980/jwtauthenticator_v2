# JupyterHub tokenauthenticator - A JWT Token Authenticator for JupyterHub

Authenticate to Jupyterhub using a query parameter for the JSONWebToken, or by an authenticating proxy that can set the Authorization header with the content of a JSONWebToken.

## Installation

This package can be installed with pip:

```
pip install jupyterhub-jwtauthenticator-v2
```

Alternately, you can clone this repository and run:

```
cd jwtauthenticator
pip install -e .
```

## Configuration

You should edit your :file:`jupyterhub_config.py` to set the authenticator class, the JSONWebTokenLocalAuthenticator provides features such as local user creation. If you already have local users then you may use the JSONWebTokenAuthenticator authenticator class:

##### For authentication and local user creation
```
c.JupyterHub.authenticator_class = 'jwtauthenticator.JSONWebTokenLocalAuthenticator'
```

This class is derived from LocalAuthenticator and therefore provides features such as the ability to add local accounts through the admin interface if configured to do so.

##### For authentication of the token only

```
c.JupyterHub.authenticator_class = 'jwtauthenticator.JSONWebTokenAuthenticator'
```

##### Required configuration

You'll also need to set some configuration options including the location of the signing certificate (in PEM format), field containing the userPrincipalName or sAMAccountName/username, and the expected audience of the JSONWebToken. This last part is optional, if you set audience to an empty string then the authenticator will skip the validation of that field.

```
# Only one of two following fields must be set.  
# If both, then "secret" will be the signing method used.
# The secrect key used to generate the given token
c.JSONWebTokenAuthenticator.secret = '<secret-key>'   
         
# -OR-
# The certificate used to sign the incoming JSONWebToken, must be in PEM Format
c.JSONWebTokenAuthenticator.signing_certificate = '/foo/bar/adfs-signature.crt'

# The claim field contianing the username/sAMAccountNAme/userPrincipalName
c.JSONWebTokenAuthenticator.username_claim_field = 'username'

# This config option should match the aud field of the JSONWebToken, empty string to disable the validation of this field.
c.JSONWebTokenAuthenticator.expected_audience = 'https://myApp.domain.local/'

# This will enable local user creation upon authentication, requires JSONWebTokenLocalAuthenticator
c.JSONWebLocalTokenAuthenticator.create_system_users = True

# Only the one of three follwing sources for JWT token must be set at the time. If you want to disable inspection
# of some of sources, set corresponding value to '' 

# URL for redirecting to in the case of invalid auth token
c.JSONWebTokenAuthenticator.auth_url = 'https://auth.example.com' 

# Name of query param for auth_url to pass return URL
c.JSONWebTokenAuthenticator.retpath_param = 'retpath' 

# Header name to retrieve JWT token
c.JSONWebTokenAuthenticator.header_name = 'X-Auth-Token'  
 
# Cookie name to retrieve JWT token                      
c.JSONWebTokenAuthenticator.cookie_name = 'auth_token'

# Query param to retrieve JWT token                         
c.JSONWebTokenAuthenticator.param_name = 'auth_token'
```

You should be able to start jupyterhub. :)

## Issues

If you have any issues or bug reports, all are welcome in the issues section. I'll do my best to respond quickly.

## Contribution

If you want to fix the bugs yourself then raise a PR and I'll take a look :)
