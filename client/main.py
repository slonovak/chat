from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random
import os.path
import json
import base64
import asyncio
from autobahn.asyncio.websocket import WebSocketClientProtocol, \
    WebSocketClientFactory


class MyClientProtocol(WebSocketClientProtocol):

    def sigGen(self, payload):
        myhash = SHA.new(payload.encode('utf8'))
        signature = PKCS1_v1_5.new(self.privatekey)
        signature = signature.sign(myhash)
        chiperrsa = PKCS1_OAEP.new(self.publickey)
        sig = chiperrsa.encrypt(signature[:128])
        sig = sig + chiperrsa.encrypt(signature[128:])
        return base64.b64encode(sig).decode('utf8')

    def sigVeryfy(self, payload, sig):
        sig = base64.b64decode(sig.encode('utf8'))
        myhash = SHA.new(payload.encode('utf8'))
        signature = PKCS1_v1_5.new(self.publickey)
        chiperrsa = PKCS1_OAEP.new(self.privatekey)
        sig = chiperrsa.decrypt(sig[:1024]) + chiperrsa.decrypt(sig[1024:])
        return signature.verify(myhash, sig)

    def rsaEnc(self, msg):
        chiperrsa = PKCS1_OAEP.new(self.publickey)
        return base64.b64encode(chiperrsa.encrypt(msg)).decode('utf8')

    def rsaDec(self, msg):
        chiperrsa = PKCS1_OAEP.new(self.privatekey)
        return chiperrsa.decrypt(base64.b64decode(msg.encode('utf8')))

    def msgEncAES(self, msg, AES_key, iv):
        msg = msg.encode('utf8')
        chiperaes = AES.new(AES_key, AES.MODE_CFB, iv)
        return base64.b64encode(chiperaes.encrypt(msg)).decode('utf8')

    def msgDecAES(self, msg, AES_key, iv):
        chiperaes = AES.new(self.rsaDec(AES_key), AES.MODE_CFB, self.rsaDec(iv))
        return chiperaes.decrypt(base64.b64decode(msg.encode('utf8'))).decode('utf8')

    def ToSend(self, msg):
        jsonMsg = dict()
        AES_key = Random.new().read(32)
        iv = Random.new().read(16)
        jsonMsg['msg'] = self.msgEncAES(msg, AES_key, iv)
        jsonMsg['msg_sig'] = self.sigGen(jsonMsg['msg'])
        jsonMsg['AES_key'] = self.rsaEnc(AES_key)
        jsonMsg['AES_key_sig'] = self.sigGen(jsonMsg['AES_key'])
        jsonMsg['iv'] = self.rsaEnc(iv)
        jsonMsg['iv_sig'] = self.sigGen(jsonMsg['iv'])
        return json.dumps(jsonMsg)

    def onConnect(self, response):
        print("Server connected: {0}".format(response.peer))

    def ToSendAuth(self):
        pass #In next versions По хешу от публичного ключа, на сервере поиск в бд

    def ToSendRSAPub(self):
        jsonMsg = dict()
        jsonMsg['pub'] = open('my_key.pub', 'r').read()
        jsonMsg['sig'] = self.sigGen(jsonMsg['pub'])
        self.sendMessage(json.dumps(jsonMsg).encode('utf8'))

    async def onOpen(self):
        self.auth_state = 0
        self.publickey = RSA.import_key(open('id.pub', 'rb').read())
        self.privatekey = RSA.import_key(open('my_key', 'rb').read())
        self.ToSendRSAPub()
        print("WebSocket connection open.")
        while True:
            msg = await loop.run_in_executor(None, input)
            self.sendMessage(self.ToSend(msg).encode('utf8'))

    def onMessage(self, payload, isBinary):
        if isBinary:
            pass
        else:
            payload = json.loads(payload.decode('utf8'))
            if self.auth_state == 0:
                if self.sigVeryfy(payload['AES_key'], payload['AES_key_sig']) and self.sigVeryfy(payload['iv'], payload['iv_sig']) and self.sigVeryfy(payload['msg'], payload['msg_sig']):
                    msg = self.msgDecAES(payload['msg'], payload['AES_key'], payload['iv'])
                    payload = {}
                    print("Text message received: {0}".format(msg))
                else:
                    print('err')


    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))


if __name__ == '__main__':
    if not(os.path.exists('my_key') and os.path.exists('my_key.pub')):
        print('RSA keys generating')
        privatekey = RSA.generate(8192)
        f = open('my_key', 'wb')
        f.write(bytes(privatekey.exportKey('PEM')))
        f.close()
        publickey = privatekey.publickey()
        f = open('my_key.pub', 'wb')
        f.write(bytes(publickey.export_key('PEM')))
        f.close()
    
    factory = WebSocketClientFactory("ws://127.0.0.1:9090")
    factory.protocol = MyClientProtocol

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(factory, '127.0.0.1:9090', 9090)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()