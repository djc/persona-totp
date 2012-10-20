# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
import unittest, persona, os

try:
	import simplejson as json
except ImportError:
	import json

KEY = RSA.importKey(open('tests.pem'))
SECRETS = json.load(open('tests.json'))

class Readable(object):
	def __init__(self, data):
		self.data = data
	def read(self):
		return self.data

def testenv(data):
	return {
		'REQUEST_METHOD': 'POST',
		'wsgi.input': Readable(data),
	}

class IdPTests(unittest.TestCase):
	
	@classmethod
	def setUpClass(self):
		persona.KEY = KEY
		persona.SECRETS = SECRETS
	
	def test_b64u(self):
		
		res = persona.b64udecode(persona.b64uencode('test'))
		assert res == 'test'
		
		res = persona.b64udecode(persona.b64uencode('a'))
		assert res == 'a'
		
		res = persona.b64udecode(persona.b64uencode('ab'))
		assert res == 'ab'
		
		res = persona.b64udecode(persona.b64uencode('abc'))
		assert res == 'abc'
		
		res = persona.b64udecode(persona.b64uencode('Iñtërnâtiônàlizætiøn'))
		assert res == 'Iñtërnâtiônàlizætiøn'
	
	def test_jws(self):
		
		jws = persona.sign({'foo': 'bar'}, persona.KEY)
		assert persona.validate(jws, persona.KEY)
		
		parts = jws.split('.')
		parts[1] = persona.b64uencode(json.dumps({'bar': 'foo'}))
		fake = '.'.join(parts)
		assert not persona.validate(fake, persona.KEY)
	
	def test_verify(self):
		
		totp = persona.totp(SECRETS['me']['totp']).pop()
		req = testenv(json.dumps({'user': 'me@example.com', 'totp': totp}))
		rsp = persona.verify(req)
		assert rsp[2]['status'] == 'okay'
		
		bad = persona.unwrap('FQVXRM3Q2JM6ECGG', rsp[2]['nonce'])
		assert not bad
	
	def test_session(self):
		
		session = persona.wrap(SECRETS['cookie'], user='me@example.com')
		req = testenv(session)
		rsp = persona.session(req)
		assert rsp[2]['user'] == 'me@example.com'
		
		dt = (datetime.utcnow() - timedelta(1)).strftime(persona.DATE_FMT)
		session = {'user': 'me@example.com', 'expires': dt}
		nonce = persona.wrap(SECRETS['cookie'], **session)
		assert not persona.unwrap(SECRETS['cookie'], nonce)
	
	def test_certificate(self):
		
		params = {'user': 'me@example.com', 'key': {'foo': 'bar'}}
		params['duration'] = 21600
		req = testenv(json.dumps(params))
		jwt = persona.certificate(req)[2]
		assert persona.validate(jwt, KEY)
		
		claims = json.loads(persona.b64udecode(jwt.split('.')[1]))
		assert claims['iss'] == 'example.com'
		assert claims['principal']['email'] == 'me@example.com'
		assert claims['exp'] - claims['iat'] == 21600000
	
	def test_hs256(self):
		key = os.urandom(20)
		jws = persona.sign({'foo': 'bar'}, key, 'HS256')
		assert persona.validate(jws, key)

if __name__ == '__main__':
    unittest.main()
