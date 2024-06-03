import datetime

from PGPMessage import PGPMessage
from user import User, users
from keyRing.keyRingManager import KeyRingManager, saveKey, loadKey

km = KeyRingManager()

gloginja = User('amarko00@hotmail.com', 'markog99', 'Marko')
users.append(gloginja)

milena = User('jmilena3110@gmail.com', 'milena123', 'Milena')
users.append(milena)

gloginja_keyID = km.generateNewPairRSA(1024, gloginja.email, 'markog99')

milena_keyID = km.generateNewPairRSA(1024, milena.email, 'milena123')

msg = PGPMessage(datetime.datetime.now(), 'Milena sta radis')
#msg.save(filePath='test.json', PR=km.getPR(gloginja_keyID, 'markog99'), PU=km.getPU(milena_keyID), isCompressed=True, algo=1, keyID=milena_keyID)
#msg.save(filePath='test.json', PR=km.getPR(gloginja_keyID, 'markog99'), PU=km.getPU(milena_keyID), isCompressed=False, algo=2, keyID=milena_keyID)
#msg.save(filePath='test.json', PR=None, PU=km.getPU(milena_keyID), isCompressed=False, algo=1, keyID=milena_keyID)
msg.save(filePath='test.json', PR=km.getPR(gloginja_keyID, 'markog99'), PU=None, isCompressed=True, algo=2, keyID=milena_keyID)


msg = PGPMessage()

msg.load(filePath='test.json', PR=km.getPR(milena_keyID, 'milena123'), PU=km.getPU(gloginja_keyID))

print(msg.message['data'])

saveKey('test.pem','jmilena3110@gmail.com', km.getPU(milena_keyID))

pu = loadKey('test.pem','jmilena3110@gmail.com')

pass
