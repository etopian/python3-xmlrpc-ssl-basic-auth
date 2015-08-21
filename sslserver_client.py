from xmlrpc.client import ServerProxy

user = 'admin'
pas = 'admin'
p = ServerProxy('https://%s:%s@localhost:8111' % (user, pas))
print(p.give_me_time())