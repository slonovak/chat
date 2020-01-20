import Crypto
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random
import socket
import select
import os.path
import json
import base64
import asyncio

from autobahn.asyncio.websocket import WebSocketServerProtocol, \
    WebSocketServerFactory


class MyServerProtocol(WebSocketServerProtocol):
    clients = []

    def sendAll(self, msg):
        if len(MyServerProtocol.clients):
            for i in MyServerProtocol.clients:
                i.sendMessage(i.ToSendWithName(msg, self.name).encode('utf8'))

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

    def ToSendWithName(self, msg, name):
        jsonMsg = dict()
        AES_key = Random.new().read(32)
        iv = Random.new().read(16)
        jsonMsg['msg'] = self.msgEncAES(msg, AES_key, iv)
        jsonMsg['msg_sig'] = self.sigGen(jsonMsg['msg'])
        jsonMsg['AES_key'] = self.rsaEnc(AES_key)
        jsonMsg['AES_key_sig'] = self.sigGen(jsonMsg['AES_key'])
        jsonMsg['iv'] = self.rsaEnc(iv)
        jsonMsg['iv_sig'] = self.sigGen(jsonMsg['iv'])
        jsonMsg['name'] = self.msgEncAES(name, AES_key, iv)
        jsonMsg['name_sig'] = self.sigGen(jsonMsg['name'])
        return json.dumps(jsonMsg)

    def onConnect(self, request):
        print("Client connecting: {0}".format(request.peer))

    def onOpen(self):
        self.auth_state = 1
        self.privatekey = RSA.import_key(open('id', 'rb').read())
        MyServerProtocol.clients.append(self)
        print("WebSocket connection open.")

    def onMessage(self, payload, isBinary):
        if isBinary:
            pass
        else:
            payload = json.loads(payload.decode('utf8'))
            if self.auth_state == 0:
                if self.sigVeryfy(payload['AES_key'], payload['AES_key_sig']) and self.sigVeryfy(payload['iv'], payload['iv_sig']) and self.sigVeryfy(payload['msg'], payload['msg_sig']):
                    msg = self.msgDecAES(payload['msg'], payload['AES_key'], payload['iv'])
                    payload = {}
                    print("{}: {}".format(self.name, msg))
                    self.sendAll(msg)
                else:
                    print('err')
            elif self.auth_state == 1:
                if 'pub' in payload.keys():
                    self.publickey = RSA.import_key(payload['pub'])
                    if self.sigVeryfy(payload['pub'], payload['sig']):
                        print('all ok')
                        self.auth_state = 2
                    else:
                        print('err')
            elif self.auth_state == 2:
                if self.sigVeryfy(payload['AES_key'], payload['AES_key_sig']) and self.sigVeryfy(payload['iv'], payload['iv_sig']) and self.sigVeryfy(payload['msg'], payload['msg_sig']):
                    self.name = self.msgDecAES(payload['msg'], payload['AES_key'], payload['iv'])
                    self.auth_state = 0
                else:
                    print('err')

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))
        MyServerProtocol.clients.remove(self)


if __name__ == '__main__':
    factory = WebSocketServerFactory("ws://127.0.0.1:9090")
    factory.protocol = MyServerProtocol

    loop = asyncio.get_event_loop()
    coro = loop.create_server(factory, '0.0.0.0', 9090)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.close()