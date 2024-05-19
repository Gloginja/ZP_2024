from keyRing.keyRingManager import KeyRingManager
import rsa
from user import User, users
pu, pr = rsa.newkeys(1024)

manager = KeyRingManager()
gloginja = User('amarko00@hotmail.com','gloginja99','Marko')
users.append(gloginja)
manager.generateNewPairRSA(1024, 'amarko00@hotmail.com', 'gloginja99')
pass

