Persona-TOTP
============

This is a small implementation of a Mozilla Persona Identity Provider (IdP).
It's designed to be secure and easy to deploy, relying on a host of standards
in web development and cryptography to handle your identity.

**WARNING:** while I've tried to make persona-totp secure, I have not had
substantial training in either security or cryptography. Be careful.

Requirements
------------

- Tested on Python 2.7 (2.6 might work, too)
- PyCrypto
- HTML5 localStorage in your browsers
- A TOTP (RFC 6238) implementation for identification
- simplejson is used for JSON operations if available

PyCrypto is currently used for cryptographic primitives. This could be swapped
out for other implementations (such as M2Crypto) by writing a few stubs.

localStorage should be `supported`_ in most fairly recent browsers. I tried it
with cookies first, but unfortunately that doesn't work if you disable
third-party cookies, which I usually do. An alternative implementation
using IndexedDB would probably be `a good idea`_.

The easiest way of using TOTP is installing the `Google Authenticator`_
application on your mobile device (click link for app store links).

.. _supported: http://caniuse.com/namevalue-storage
.. _a good idea: https://blog.mozilla.org/tglek/2012/02/22/psa-dom-local-storage-considered-harmful/
.. _Google Authenticator: http://code.google.com/p/google-authenticator/

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
  "me" is the local part of an email address (i.e. me@example.com).
  
  You should also install the TOTP key in the TOTP client at this point.
  In Google Authenticator, use "Set up account", then "Enter provided key".
  Use your email address as the account name (though this isn't actually
  used) and the generated secret as your key.

- Create a support document:

    $ python persona.py support > browserid

  Save it in the .well-known directory on your email domain. Serving it
  correctly isn't trivial, so find `some tips`_ online.

- Run the application() callable from persona.py as a WSGI application
  and make sure the URLs in the support document point at it. Make sure
  to keep your secrets.json and private.pem private!

.. _some tips: https://developer.mozilla.org/en-US/docs/Persona/IdP_Development_Tips

Further information
-------------------

persona-totp was created by Dirkjan Ochtman. It is `hosted`_ at Github;
please report any issues there (or better yet, send me a pull request!).

.. _hosted: https://github.com/djc/persona-totp

Changes
-------

Changes in 0.3 (2014-04-23)

* Make sure we don't include script from a random host
* Only allow certificate to be built from a currently valid session
* Implement slow comparison method to defend against timing attacks

Thanks to rhy-jot for pointing out security problems fixed in this version.

Changes in 0.2 (2012-10-20)

* Add a test suite
* Refactor WSGI application, for less code repetition and easier testing
* Improved handling of Unicode strings
* Support HS256 algorithm for JWS
* Slightly improved documentation
