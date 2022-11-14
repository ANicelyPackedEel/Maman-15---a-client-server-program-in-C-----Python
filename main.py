import os
import sys
from os.path import exists
from datetime import datetime
import threading
import socket
import struct
import sqlite3
from enum import Enum
import uuid
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import crc

# constants
SERVER_VERSION = 3
DATABASE_NAME = "server.db"
PORT_FILE_PATH = "port.info"
CLIENTS_FOLDER = './clients/'
MAX_PORT_NUM = 65535
DEFAULT_PORT = 1234
REQUEST_HEADER_SIZE = 23
RESPONSE_HEADER_SIZE = 7
NAME_AND_FILE_NAME_FIELD_LENGTH = 255
ID_AND_AES_KEY_LENGTH = 16
SIZE_FIELD_SIZE = 4
PUBLIC_KEY_LENGTH = 160

lock = threading.Lock()

# create copy of db on memory
try:
    memoryDBConn = sqlite3.connect(':memory:')
except sqlite3.Error:
    raise SystemExit("Fatal error: couldn't ram create database.")


class RequestCode(Enum):
    registerRequest = 1100
    publicKeyRequest = 1101
    fileRequest = 1103
    validCRCRequest = 1104
    invalidCRCResendingRequest = 1105
    invalidCRCDoneRequest = 1106


class ResponseCode(Enum):
    registerSuccessResponse = 2100
    registerFailedResponse = 2101
    publicKeyReceivedResponse = 2102
    validCRCResponse = 2103
    messageReceivedResponse = 2104


class ResponseHeader:
    def __init__(self, code, payloadSize):
        self.version = SERVER_VERSION
        self.code = code
        self.payloadSize = payloadSize

    def ToBytesWithPayload(self, payload):  # Packing the request in little endian for sending
        if payload == '':
            return struct.pack('<BHL', self.version, self.code, self.payloadSize)
        return struct.pack(f'<BHL{self.payloadSize}s', self.version, self.code, self.payloadSize, payload)


# get port from port.info
def getPort():
    if not exists(PORT_FILE_PATH):
        print("Couldn't find 'port.info', using default port (1234).", file=sys.stderr)
        return DEFAULT_PORT
    try:
        with open(PORT_FILE_PATH, 'r') as portFile:
            content = portFile.read()
            if (not content.isnumeric()) or (int(content) > MAX_PORT_NUM):
                print("'port.info' is corrupted, using default port (1234).", file=sys.stderr)
                return DEFAULT_PORT
    except IOError:
        print("Couldn't open or read 'port.info', using default port (1234).", file=sys.stderr)
        return DEFAULT_PORT
    return content


# delete a file if crc isn't valid
def deleteFile(connection, uid, fileName):
    path = 0
    lock.acquire()
    try:
        dbConn = sqlite3.connect(DATABASE_NAME)
        c = dbConn.cursor()
        c.execute('''SELECT PathName FROM files WHERE id = ? AND fileName = ?;''', (uid, fileName))
        row = c.fetchall()
        if row:
            path = row[0][0].rsplit('\\')[1]
        c.execute('''DELETE FROM files WHERE id = ? AND fileName = ?;''',
                  (uid, fileName))
        dbConn.commit()
        dbConn.backup(memoryDBConn)
    except sqlite3.Error:
        lock.release()
        connection.close()
        print("Couldn't open the database h. stopping thread.", file=sys.stderr)
        sys.exit()

    if os.path.exists(CLIENTS_FOLDER + uid.hex() + '\\' + str(path)):
        os.remove(CLIENTS_FOLDER + uid.hex() + '\\' + str(path))
    lock.release()


# handle all the requests
def clientHandler(connection, date_time):
    # get a request
    header, payload = getAndUnpackRequest(connection)
    requestCode = header[2]
    # if a register request, register. if error try up to 3 times
    if requestCode == RequestCode.registerRequest.value:
        i = 0
        while True:
            # get name payload
            name = struct.unpack('<' + str(NAME_AND_FILE_NAME_FIELD_LENGTH) + 's', payload)[0]
            # handle registration request and sent next response
            sentCode = registrationRequestHandler(connection, name, date_time)
            i += 1
            if (sentCode == ResponseCode.registerSuccessResponse.value) or (i > 2):  # 2 - retry num
                break
            # get a request
            header, payload = getAndUnpackRequest(connection)
        # get a request
        header, payload = getAndUnpackRequest(connection)

    unpacked = struct.unpack('<' + str(NAME_AND_FILE_NAME_FIELD_LENGTH) + 's' + str(PUBLIC_KEY_LENGTH) + 's', payload)
    pubKey = unpacked[1]  # get public key from payload
    clientName = unpacked[0]  # get client name from payload
    # handle public key request and sent next response
    sendPublicKeyRequestHandler(connection, pubKey, date_time, header[0], clientName)

    # get file request up to 3 times if crc isn't valid
    i = 0
    while True:
        # get a request
        header, payload = getAndUnpackRequest(connection)
        unpackedPayload = struct.unpack(
            f'<{ID_AND_AES_KEY_LENGTH}sL{NAME_AND_FILE_NAME_FIELD_LENGTH}s{len(payload) - NAME_AND_FILE_NAME_FIELD_LENGTH - ID_AND_AES_KEY_LENGTH - 4}s',
            payload)
        encFile = unpackedPayload[3]  # get encrypted file from payload
        fileName = unpackedPayload[2]  # get file name from payload

        # deleting file from table if already there for possible resending
        deleteFile(connection, header[0], fileName)
        # handle file request and sent next response
        sendFileRequestHandler(connection, encFile, fileName, date_time, header[0])
        # get a request
        header, payload = getAndUnpackRequest(connection)
        # handle crc request
        crcRequestsHandler(connection, date_time, header[0])
        i += 1
        # if crc is valid or more than 3 tries stop receiving
        if (header[2] == RequestCode.validCRCRequest.value) or (
                header[2] == RequestCode.invalidCRCDoneRequest.value) or (i > 2):
            break
    # if crc is valid send 2104 response code - message received
    if header[2] == RequestCode.validCRCRequest.value:
        sendAccepted(connection, fileName, header[0])
    else:
        # if crc isn't valid delete the file that was saved
        deleteFile(connection, header[0], fileName)
    # close the connection and exit thread
    connection.close()


# method must be thread-locked
def saveFile(file, fileName, uid):
    path = 0
    # check if a file with the same name already exists for uid in the database
    try:
        dbConn = sqlite3.connect(DATABASE_NAME)
        c = dbConn.cursor()
        c.execute('''SELECT fileName FROM files WHERE ID = ?;''', (uid,))
        # check if file with same name already exists in db, if so, don't save.
        # also calculate file name for new file (number of rows + 1)
        for row in c:
            path += 1
            if row[0] == fileName:  # TODO: is it how you access rows? with [num]
                lock.release()
                print("File with same name already exists. stopping thread.", file=sys.stderr)
                sys.exit()
    except sqlite3.Error:
        lock.release()
        print("Couldn't open the database. stopping thread.", file=sys.stderr)
        sys.exit()
    path += 1
    # if client folder doesn't exist, create it and save file, else save file in that folders
    if os.path.exists(CLIENTS_FOLDER + uid.hex()):
        with open(CLIENTS_FOLDER + uid.hex() + '\\' + str(path), 'wb') as f:
            f.write(file)
    else:
        os.mkdir(CLIENTS_FOLDER + uid.hex())
        with open(CLIENTS_FOLDER + uid.hex() + '\\' + str(path), 'wb') as f:
            f.write(file)
    # return the path of the file
    return CLIENTS_FOLDER + uid.hex() + '\\' + str(path)


# unpack header and split payload from socket
def getAndUnpackRequest(connection):
    try:
        packedHeader = connection.recv(REQUEST_HEADER_SIZE)
        header = struct.unpack('<16sBHL', packedHeader)
        payload = connection.recv(header[3])
    except socket.error:
        print("Couldn't receive the data, stopping thread.", file=sys.stderr)
        sys.exit()
    return header, payload


# handle the register request, returns the code of the response sent
def registrationRequestHandler(connection, name, date_time):
    # connect to db
    lock.acquire()
    try:
        dbConn = sqlite3.connect(DATABASE_NAME)
        c = dbConn.cursor()
        c.execute("""SELECT EXISTS(SELECT 1 FROM clients WHERE Name=?);""", (name,))  # check if username exists in db
    except sqlite3.Error:
        lock.release()
        connection.close()
        print("Couldn't open the database. stopping thread.", file=sys.stderr)
        sys.exit()

    if not c.fetchall()[0][0]:  # if username not exists in db
        # generate uid and send register success
        uid = uuid.uuid4().bytes
        # insert the client's name, uid and the timestamp to db
        try:
            c.execute('''INSERT INTO clients(ID, Name, PublicKey, LastSeen, AESKey) VALUES (?, ?, ?, ?, ?);''',
                      (uid, name, None, datetime.timestamp(date_time), None))
            dbConn.commit()
            dbConn.backup(memoryDBConn)
            dbConn.close()
        except sqlite3.Error:
            lock.release()
            connection.close()
            print("Couldn't write to the database. stopping thread.", file=sys.stderr)
            sys.exit()
        lock.release()
        # send registered successfully response to client
        header = ResponseHeader(ResponseCode.registerSuccessResponse.value, len(uid))
        try:
            connection.send(header.ToBytesWithPayload(uid))
        except socket.error:
            connection.close()
            print("Couldn't send the data, stopping thread.", file=sys.stderr)
            sys.exit()
        return ResponseCode.registerSuccessResponse.value
    else:  # if username exists in db
        dbConn.close()
        lock.release()
        # send register error response to client
        header = ResponseHeader(ResponseCode.registerFailedResponse.value, 0)
        try:
            connection.send(header.ToBytesWithPayload(''))
        except socket.error:
            connection.close()
            print("Couldn't send the data, stopping thread.", file=sys.stderr)
            sys.exit()
        return ResponseCode.registerFailedResponse.value


# handle public key request
def sendPublicKeyRequestHandler(connection, pubKey, date_time, uid, name):
    # generate aes key
    AESKey = get_random_bytes(ID_AND_AES_KEY_LENGTH)

    # update database
    lock.acquire()
    try:
        dbConn = sqlite3.connect(DATABASE_NAME)
        c = dbConn.cursor()
        c.execute('''SELECT * FROM clients WHERE id = ?;''', (uid,))
        # if uid isn't registered, save the user in db, else, update their row
        if not c.fetchall():
            c.execute('''INSERT INTO clients(ID, NAME, PublicKey, LastSeen, AESKey) VALUES (?, ?, ?, ?, ?);''',
                      (uid, name, pubKey, datetime.timestamp(date_time), AESKey))
        else:
            c.execute('''UPDATE clients SET PublicKey = ?, LastSeen = ?, AESKey = ?  WHERE ID = ?;''',
                      (pubKey, datetime.timestamp(date_time), AESKey, uid))
        dbConn.commit()
        dbConn.backup(memoryDBConn)
        dbConn.close()
    except sqlite3.Error:
        lock.release()
        connection.close()
        print("Couldn't open, read or write to the database. stopping thread.", file=sys.stderr)
        sys.exit()
    lock.release()

    # encrypt aes key with the public key and send it
    key = RSA.importKey(pubKey)
    cipher = PKCS1_OAEP.new(key)
    encryptedAESKey = cipher.encrypt(AESKey)
    # send response with aes key
    header = ResponseHeader(ResponseCode.publicKeyReceivedResponse.value, len(encryptedAESKey) + len(uid))
    payload = struct.pack(f'<{ID_AND_AES_KEY_LENGTH}s{len(encryptedAESKey)}s', uid, encryptedAESKey)
    connection.send(header.ToBytesWithPayload(payload))


# handle file request
def sendFileRequestHandler(connection, encFile, fileName, date_time, uid):
    lock.acquire()
    try:
        dbConn = sqlite3.connect(DATABASE_NAME)
        c = dbConn.cursor()
        # update timestamp for client
        c.execute('''UPDATE clients SET LastSeen = ? WHERE ID = ?;''',
                  (datetime.timestamp(date_time), uid))
        # get aes key from db
        c.execute('''SELECT AESKey FROM clients WHERE ID = ?;''',
                  (uid,))
        AESKey = c.fetchall()[0][0]
        dbConn.commit()
        dbConn.backup(memoryDBConn)
    except sqlite3.Error:
        lock.release()
        connection.close()
        print("Couldn't open the database. stopping thread.", file=sys.stderr)
        sys.exit()
    lock.release()

    iv = bytes(ID_AND_AES_KEY_LENGTH)  # create iv 0 with length 16
    # decrypt file from request
    cipher = AES.new(AESKey, AES.MODE_CBC, iv)
    file = unpad(cipher.decrypt(encFile), AES.block_size)

    # calculate crc
    digest = crc.crc32()
    i = 1
    buf = file[:4096]
    while buf:  # TODO: move 4096 to constant
        digest.update(buf)
        i += 1
        buf = file[4096 * (i - 1):4096 * i]
    checksum = digest.digest()  # TODO: no need for checksum variable, right?
    # save file to disk
    lock.acquire()
    filePath = saveFile(file, fileName, uid)
    try:
        # save file to db, unverified
        dbConn = sqlite3.connect(DATABASE_NAME)
        c = dbConn.cursor()
        c.execute('''INSERT INTO files(ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?);''',
                  (uid, fileName, filePath, 0))
        dbConn.commit()
        dbConn.backup(memoryDBConn)
    except sqlite3.Error:
        lock.release()
        connection.close()
        print("Couldn't open the database. stopping thread.", file=sys.stderr)
        sys.exit()
    lock.release()

    # send response
    payload = struct.pack(f'<{ID_AND_AES_KEY_LENGTH}sL{NAME_AND_FILE_NAME_FIELD_LENGTH}sL',
                          uid, len(encFile), fileName, checksum)
    header = ResponseHeader(ResponseCode.validCRCResponse.value, len(payload))
    try:
        connection.send(header.ToBytesWithPayload(payload))
    except socket.error:
        connection.close()
        print("Couldn't send the data, stopping thread.", file=sys.stderr)
        sys.exit()


# handle all crc requests (update timestamp for client)
def crcRequestsHandler(connection, date_time, uid):
    lock.acquire()
    try:
        dbConn = sqlite3.connect(DATABASE_NAME)
        c = dbConn.cursor()
        c.execute('''UPDATE clients SET LastSeen = ? WHERE ID = ?;''',
                  (datetime.timestamp(date_time), uid))
        dbConn.commit()
        dbConn.backup(memoryDBConn)
    except sqlite3.Error:
        lock.release()
        connection.close()
        print("Couldn't open the database. stopping thread.", file=sys.stderr)
        sys.exit()
    lock.release()


def sendAccepted(connection, fileName, uid):
    try:
        dbConn = sqlite3.connect(DATABASE_NAME)
        c = dbConn.cursor()
        # update file sent to verified
        c.execute('''UPDATE files SET Verified = 1 WHERE id = ? AND fileName = ?;''',
                  (uid, fileName))
        dbConn.commit()
        dbConn.backup(memoryDBConn)
    except sqlite3.Error:
        lock.release()
        connection.close()
        print("Couldn't open the database. stopping thread.", file=sys.stderr)
        sys.exit()

    # send 2104 response - message received
    header = ResponseHeader(ResponseCode.messageReceivedResponse.value, 0)
    try:
        connection.send(header.ToBytesWithPayload(''))
    except socket.error:
        connection.close()
        print("Couldn't send the data, stopping thread.", file=sys.stderr)


# create the db if it doesn't exist
def createDB():
    dbConn = sqlite3.connect(DATABASE_NAME)
    c = dbConn.cursor()

    # create tables if they don't exist
    c.execute(
        '''CREATE TABLE IF NOT EXISTS clients (ID BLOB PRIMARY KEY NOT NULL, Name BLOB NOT NULL, PublicKey BLOB, LastSeen REAL NOT NULL, AESKey BLOB);''')
    c.execute(
        '''CREATE TABLE IF NOT EXISTS files (ID BLOB NOT NULL, FileName BLOB NOT NULL, PathName TEXT UNIQUE NOT NULL, Verified INTEGER NOT NULL, PRIMARY KEY (ID, FIleName));''')  # TODO: what combination should be the primary key??

    dbConn.commit()
    dbConn.backup(memoryDBConn)
    dbConn.close()


if __name__ == '__main__':

    # create db on first run
    createDB()

    port = int(getPort())
    host = ''

    # create folder to store client's files if it doesn't exist
    if not os.path.exists(CLIENTS_FOLDER):
        os.mkdir(CLIENTS_FOLDER)

    try:  # create socket and listen for connections
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)  # TODO: what number to put into listen?
    except socket.error:
        raise SystemExit("Fatal error: an unexpected socket error occurred.")

    threads = []

    try:
        while True:
            # accept client connection
            conn, addr = s.accept()
            # create a thread per client and run it
            thread = threading.Thread(target=clientHandler, args=[conn, datetime.now()])
            thread.start()
            threads.append(thread)
    except KeyboardInterrupt:
        print("Stopped by Ctrl+C.")
    finally:
        # close socket and wait for threads to finish
        if s:
            s.close()
        for thread in threads:
            thread.join()

    # close memory db that holds a copy of the main db
    memoryDBConn.close()
