Persona-TOTP
============

This is a small implementation of a Mozilla Persona Identity Provider (IdP).
It's designed to be secure and easy to deploy, relying on a host of standards
in web development and cryptography to handle your identity.

Requirements
------------

- Python 2.7
- PyCrypto
- HTML5 localStorage in your browsers
- A TOTP (RFC 6238) implementation for identification
- simplejson is used for JSON operations if available

PyCrypto is currently used for cryptographic primitives. This could be swapped
out for other implementations (such as M2Crypto) by writing a few stubs.
localStorage should be supported in most fairly recent browsers, see
http://caniuse.com/namevalue-storage. An alternative implementation using
IndexedDB would probably be a good idea, see
https://blog.mozilla.org/tglek/2012/02/22/psa-dom-local-storage-considered-harmful/.
The easiest way of using TOTP is installing the Google Authenticator
application on your mobile device.

How to install
--------------

- Generate an RSA key pair:

    $ openssl genrsa -out private.pem 2048

  persona.py currently looks for it in its own directory, as private.pem.

- Generate a secret to sign the (localStorage) cookie

    >>> base64.b16encode(os.urandom(20))
    '7C6E15B8CDB3941A9117825E492FE1C713411B12'
    
- For each user on your domain, generate a secret to use with TOTP

    >>> base64.b32encode(os.urandom(10))
    '2Q53Z3XJI7MJKNR7'

- Save the secrets in a JSON file, like this:

    {
      "cookie": "7C6E15B8CDB3941A9117825E492FE1C713411B12",
      "me": {
          "totp": "2Q53Z3XJI7MJKNR7"
      }
    }

  persona.py currently looks for it in its own directory, as secrets.json.

- Create a support document:

    $ python persona.py support > browserid

  Save it in the .well-known directory on your email domain. See
  https://developer.mozilla.org/en-US/docs/Persona/IdP_Development_Tips
  for some tips on how to serve it correctly.

- Run the application() callable from persona.py as a WSGI application
  and make sure the URLs in the support document point at it.
