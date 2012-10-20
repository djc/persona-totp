from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

import base64, hashlib, hmac, os, struct, time, urlparse, sys

try:
	import simplejson as json
except ImportError:
	import json

EXPIRES = 30 # days
STORAGE_KEY = 'Persona-TOTP'
DATE_FMT = '%Y-%m-%d %H:%M:%S'

DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS = json.load(open(os.path.join(DIR, 'secrets.json')))
KEY = RSA.importKey(open(os.path.join(DIR, 'private.pem')))

def bytestr(s, enc='ascii'):
	return s.encode(enc) if isinstance(s, unicode) else s

# Some bits for JWS

def b64uencode(s):
	return base64.urlsafe_b64encode(bytestr(s, 'utf-8')).replace('=', '')

def b64udecode(s):
	s = bytestr(s) + '=' * (4 - (len(s) % 4))
	return base64.urlsafe_b64decode(s)

def sign(payload, key):
	h = json.dumps({'alg': 'RS256'})
	input = b64uencode(h) + '.' + b64uencode(json.dumps(payload))
	sig = PKCS1_v1_5.new(key).sign(SHA256.new(input))
	return input + '.' + b64uencode(sig)

def validate(token, key):
	parts = token.split('.')
	h = json.loads(b64udecode(parts[0]))
	assert h['alg'] == 'RS256'
	input = SHA256.new('.'.join(parts[:2]))
	return PKCS1_v1_5.new(key).verify(input, b64udecode(parts[2]))

# Functions for secure cookies

def wrap(secret, **vals):
	expires = datetime.utcnow() + timedelta(EXPIRES)
	if 'expires' not in vals:
		vals['expires'] = expires.strftime(DATE_FMT)
	data = b64uencode(json.dumps(vals))
	sig = b64uencode(hmac.new(bytestr(secret), data, hashlib.sha1).digest())
	return data + '.' + sig

def unwrap(secret, s):
	
	data, sig = s.split('.')
	new = b64uencode(hmac.new(bytestr(secret), data, hashlib.sha1).digest())
	if new != sig:
		return {}
	
	data = json.loads(b64udecode(data))
	now = datetime.utcnow().strftime(DATE_FMT)
	if now > data['expires']:
		return {}
	
	return data

# Functions for HOTP/TOTP

def hotp(secret, ivals):
	key = base64.b32decode(secret)
	msg = struct.pack('>Q', ivals)
	h = hmac.new(key, msg, hashlib.sha1).digest()
	o = ord(h[19]) & 15
	return (struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000

def totp(secret, tolerance=0):
	values = set()
	for i in range(-tolerance, tolerance + 1):
		ivals = (int(time.time()) + (i * 30)) // 30
		values.add('%06i' % hotp(secret, ivals))
	return values

# Putting it all together: WSGI

def render(tmpl, vars):
	with open(os.path.join(DIR, tmpl)) as f:
		src = f.read()
		for k, v in vars.iteritems():
			src = src.replace('{{ %s }}' % k, v)
		return src

def provision(env):
	return 200, 'provision.html'

def authenticate(env):
	return 200, 'authenticate.html'

def verify(env):
	
	assert env['REQUEST_METHOD'] == 'POST'
	data = json.loads(env['wsgi.input'].read())
	user = data['user'].split('@', 1)[0]
	secret = SECRETS[user]['totp'].encode('utf-8')
	
	if data['totp'] in totp(secret, 1):
		session = wrap(SECRETS['cookie'], user=data['user'])
		return 200, 'json', {'status': 'okay', 'nonce': session}
	else:
		return 200, 'json', {'status': 'failed'}

def session(env):
	assert env['REQUEST_METHOD'] == 'POST'
	return 200, 'json', unwrap(SECRETS['cookie'], env['wsgi.input'].read())
	
def certificate(env):
	
	assert env['REQUEST_METHOD'] == 'POST'
	params = json.loads(env['wsgi.input'].read())
	host = params['user'].split('@')[1]
	
	claims = {'iss': host, 'public-key': params['key']}
	duration = min(24 * 60 * 60, params['duration'])
	claims['iat'] = int(time.time()) * 1000
	claims['exp'] = claims['iat'] + duration * 1000
	claims['principal'] = {'email': params['user']}
	return 200, 'text', sign(claims, KEY)

handlers = {
	'provision': provision, 'authenticate': authenticate, 'verify': verify,
	'session': session, 'certificate': certificate,
}

def application(env, respond):
	
	rsp = 404, 'text', 'not found'
	pi = [] if not env['PATH_INFO'] else env['PATH_INFO'].strip('/').split('/')
	if pi and pi[0] in handlers:
		rsp = handlers[pi[0]](env)
	
	if rsp[1].endswith('.html'):
		headers = {'Content-Type': 'text/html; charset=utf-8'}
		persona = 'login.persona.org'
		if env.get('HTTP_REFERER'):
			persona = urlparse.urlparse(env['HTTP_REFERER']).netloc
		content = render(rsp[1], {'key': STORAGE_KEY, 'persona': persona})
	
	elif rsp[1] == 'json':
		headers = {'Content-Type': 'application/json'}
		content = json.dumps(rsp[2])
	
	elif rsp[1] == 'text':
		headers = {'Content-Type': 'text/plain; charset=utf-8'}
		content = rsp[2]
	
	status = {200: '200 OK', 404: '404 Not Found'}
	respond(status[rsp[0]], headers.items())
	return [content]

# Some command-line utilities

def support():
	doc = {
		'public-key': {
			'algorithm': 'RS',
			'n': str(KEY.n),
			'e': str(KEY.e),
		},
		'authentication': '/persona/authenticate',
		'provisioning': '/persona/provision',
	}
	print json.dumps(doc, indent=2)

COMMANDS = {'support': support}

if __name__ == '__main__':
	if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
		print 'Usage: python %s %s' % (__file__, '|'.join(COMMANDS.keys()))
	else:
		COMMANDS[sys.argv[1]]()
