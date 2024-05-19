from keyRing.privateKeyRing import PrivateKeyRing
import rsa
import user
from datetime import datetime
pr, pu = rsa.newkeys(1024)

pkr = PrivateKeyRing()
gloginja = user.User('amarko00@hotmail.com','gloginja99','Marko')
user.users.append(gloginja)
pkr.addToRing(datetime.now(), pr, pu, gloginja.email)
pr1 = pkr.getPR(pu.n % 2 ** 64, 'gloginja99')
pass

