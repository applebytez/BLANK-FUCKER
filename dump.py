from __future__ import print_function
import os
import struct
import marshal
import zlib
import sys
from uuid import uuid4 as uniquename
import subprocess
import re
import base64
from pyaes import AESModeOfOperationGCM
from zipfile import ZipFile
import lzma
import time
import os
import shutil

class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b'\0' * 4
        self.barePycList = []  # List of pyc's whose headers have to be fixed

    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            return False
        return True

    def close(self):
        try:
            self.fPtr.close()
        except:
            pass

    def checkFile(self):
        print('[BLANC-FUCKER] Processing {0}'.format(self.filePath))

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            print(
                '[BLANC-FUCKER] Error : Missing cookie, unsupported pyinstaller version or not a pyinstaller archive')
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b'python' in self.fPtr.read(64).lower():
            print('[BLANC-FUCKER] Pyinstaller version: 2.1+')
            self.pyinstVer = 21     # pyinstaller 2.1+
        else:
            self.pyinstVer = 20     # pyinstaller 2.0
            print('[BLANC-FUCKER] Pyinstaller version: 2.0')

        return True

    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = \
                    struct.unpack('!8siiii', self.fPtr.read(
                        self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = \
                    struct.unpack('!8sIIii64s', self.fPtr.read(
                        self.PYINST21_COOKIE_SIZE))

        except:
            print('[BLANC-FUCKER] Error : The file is not a pyinstaller archive')
            return False

        self.pymaj, self.pymin = (pyver//100, pyver %
                                  100) if pyver >= 100 else (pyver//10, pyver % 10)
        print('[BLANC-FUCKER] Python version: {0}.{1}'.format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = self.fileSize - self.cookiePos - \
            (self.PYINST20_COOKIE_SIZE if self.pyinstVer ==
             20 else self.PYINST21_COOKIE_SIZE)

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print('[BLANC-FUCKER] Length of package: {0} bytes'.format(lengthofPackage))
        return True

    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iIIIBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
                struct.unpack(
                '!IIIBc{0}s'.format(entrySize - nameLen),
                self.fPtr.read(entrySize - 4))

            name = name.decode('utf-8').rstrip('\0')

            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                print(
                    '[BLANC-FUCKER] Warning: Found an unamed file in CArchive. Using random name {0}'.format(name))

            self.tocList.append(
                CTOCEntry(
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name
                ))

            parsedLen += entrySize
        print('[BLANC-FUCKER] Found {0} files in CArchive'.format(len(self.tocList)))

    def _writeRawData(self, filepath, data):
        nm = filepath.replace('\\', os.path.sep).replace(
            '/', os.path.sep).replace('..', '__')
        nmDir = os.path.dirname(nm)
        # Check if path exists, create if not
        if nmDir != '' and not os.path.exists(nmDir):
            os.makedirs(nmDir)

        with open(nm, 'wb') as f:
            f.write(data)

    def extractFiles(self):
        print('[BLANC-FUCKER] Beginning extraction...please standby')
        extractionDir = os.path.join(
            os.getcwd(), os.path.basename(self.filePath) + '_extracted')

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    print(
                        '[BLANC-FUCKER] Error : Failed to decompress {0}'.format(entry.name))
                    continue
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize  # Sanity Check

            if entry.typeCmprsData == b'd' or entry.typeCmprsData == b'o':
                # d -> ARCHIVE_ITEM_DEPENDENCY
                # o -> ARCHIVE_ITEM_RUNTIME_OPTION
                # These are runtime options, not files
                continue

            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry.typeCmprsData == b's':
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                print('[BLANC-FUCKER] Possible entry point: {0}.pyc'.format(entry.name))

                if self.pycMagic == b'\0' * 4:
                    # if we don't have the pyc header yet, fix them in a later pass
                    self.barePycList.append(entry.name + '.pyc')
                self._writePyc(entry.name + '.pyc', data)

            elif entry.typeCmprsData == b'M' or entry.typeCmprsData == b'm':
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header intact

                # From PyInstaller 5.3 and above pyc headers are no longer stored
                # https://github.com/pyinstaller/pyinstaller/commit/a97fdf
                if data[2:4] == b'\r\n':
                    # < pyinstaller 5.3
                    if self.pycMagic == b'\0' * 4:
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + '.pyc', data)

                else:
                    # >= pyinstaller 5.3
                    if self.pycMagic == b'\0' * 4:
                        # if we don't have the pyc header yet, fix them in a later pass
                        self.barePycList.append(entry.name + '.pyc')

                    self._writePyc(entry.name + '.pyc', data)

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                    self._extractPyz(entry.name)

        # Fix bare pyc's if any
        self._fixBarePycs()

    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, 'r+b') as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)

    def _writePyc(self, filename, data):
        with open(filename, 'wb') as pycFile:
            pycFile.write(self.pycMagic)            # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:                # PEP 552 -- Deterministic pycs
                pycFile.write(b'\0' * 4)        # Bitfield
                pycFile.write(b'\0' * 8)        # (Timestamp + size) || hash

            else:
                pycFile.write(b'\0' * 4)      # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    # Size parameter added in Python 3.3
                    pycFile.write(b'\0' * 4)

            pycFile.write(data)

    def _extractPyz(self, name):
        dirName = name + '_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0'  # Sanity Check

            pyzPycMagic = f.read(4)  # Python magic value

            if self.pycMagic == b'\0' * 4:
                self.pycMagic = pyzPycMagic

            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
                print(
                    '[BLANC-FUCKER] Warning: pyc magic of files inside PYZ archive are different from those in CArchive')

            # Skip PYZ extraction if not running under the same python version
            if self.pymaj != sys.version_info.major or self.pymin != sys.version_info.minor:
                print(
                    '[BLANC-FUCKER] Warning: This script is running in a different Python version than the one used to build the executable.')
                print('[BLANC-FUCKER] Please run this script in Python {0}.{1} to prevent extraction errors during unmarshalling'.format(
                    self.pymaj, self.pymin))
                print('[BLANC-FUCKER] Skipping pyz extraction')
                return

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print(
                    '[BLANC-FUCKER] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.'.format(name))
                return

            print('[BLANC-FUCKER] Found {0} files in PYZ archive'.format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode('utf-8')
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace(
                    '..', '__').replace('.', os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')

                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[BLANC-FUCKER] Error: Failed to decompress {0}, probably encrypted. Extracting as is.'.format(
                        filePath))
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)

def assemblyOfFile(path):
  result = subprocess.run(['/Users/user/Documents/Projects/Blanc-Reverser/pycdas', path], stdout=subprocess.PIPE)
  return result.stdout

def decryptAES(key, iv, ciphertext):
  return AESModeOfOperationGCM(key, iv).decrypt(ciphertext)

def cleanup():
    print("[BLANC-FUCKER] Saying goodbye to shit malware...")
    shutil.rmtree(os.getcwd())

def deobfuscate(pyfile):
    print("[BLANC-FUCKER] Starting deobfuscation process...")
    pyCode = ""
    with open(pyfile, "r") as f:
        pyCode = f.read()
    pyCode = pyCode.replace('__import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([89, 110, 86, 112, 98, 72, 82, 112, 98, 110, 77, 61])).decode()).exec(__import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([98, 87, 70, 121, 99, 50, 104, 104, 98, 65, 61, 61])).decode()).loads(__import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([89, 109, 70, 122, 90, 84, 89, 48])).decode()).b64decode(__import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([89, 50, 57, 107, 90, 87, 78, 122])).decode()).decode(____, __import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([89, 109, 70, 122, 90, 84, 89, 48])).decode()).b64decode("cm90MTM=").decode())+_____+______[::-1]+_______)))', 'import importlib, sys;import base64;import codecs;import marshal;code = importlib._bootstrap_external._code_to_timestamp_pyc(marshal.dumps(base64.b64decode(codecs.decode(____, "rot13")+_____+______[::-1]+_______)));\nwith open("dump.pyc", "wb") as f:\n  f.write(code)')
    with open(pyfile, "w") as f:
        f.write(pyCode)
    result = subprocess.run(['python3', pyfile], stdout=subprocess.PIPE)
    asm = assemblyOfFile("dump.pyc")
    with open('asm.txt', 'wb') as f:
        f.write(asm)
    
    with open("dump.pyc", "rb") as f:
        byteCode = f.read()
        partialWebhook = re.findall(r"(?<=xa4aH)(.*?)(?==z)", str(byteCode))[0]
        webhook = "aH"+partialWebhook+"="
        write_path = os.path.abspath(os.path.join(os.getcwd(), '..'))
        with open(write_path+"/we_gottem.hook", "w") as f:
            f.write(str(base64.b64decode(webhook)).replace("b'", "").replace("'", ""))
            print("[BLANC-FUCKER] Webhook: "+str(base64.b64decode(webhook)).replace("b'", "").replace("'", ""))
        cleanup()
    

def decrypt():
    path = "/Users/user/Documents/Projects/Blanc-Reverser/grabber.exe_extracted/"
    mainStub = path+"/blank.aes"
    loader = path+"/loader-o.pyc"
    loaderAssembly = str(assemblyOfFile(loader))
    strings = re.findall(r"(?<= ').+?(?=')", loaderAssembly)
    foundBase64 = []
    for match in strings:
        if len(match) > 10:
            try:
                string = base64.b64decode(match)
                if string not in foundBase64:
                    foundBase64.append(string)
            except: 
                print("[BLANC-FUCKER] Matching string is not key or IV!")
    if len(foundBase64) < 2:
        print("[BLANC-FUCKER] Could not find keys")
    else:
        key = ""
        iv = ""
        if len(foundBase64[0]) > len(foundBase64[1]):
            key = foundBase64[0]
            iv = foundBase64[1]
        else:
            key = foundBase64[1]
            iv = foundBase64[0]
        if os.path.isfile(mainStub):
            with open(mainStub, "rb") as f:
                ciphertext = f.read()
                decrypted = decryptAES(key, iv, ciphertext)
                with open("stub.zip", "wb") as f:
                    f.write(decrypted)
                with ZipFile("stub.zip", 'r') as zObject:
                    zObject.extractall()
            stubAssembly = assemblyOfFile(path+"stub-o.pyc")
            lines = stubAssembly.splitlines(keepends=False)
            for line in lines:
                if "LOAD_CONST" in str(line):
                    possibleHex = re.sub(b"        [0-9][0-9][0-9][0-9]    LOAD_CONST                    [0-9]: ", b'', line)
                    if len(possibleHex) > 200:
                        code = eval(possibleHex)
                        obj = lzma.LZMADecompressor()
                        with open("decrypted.py", "wb") as f:
                            f.write(obj.decompress(code))
                        print("[BLANC-FUCKER] Ladies and gentleman....")
                        time.sleep(1)
                        print("[BLANC-FUCKER] We got him..")
                        deobfuscate(path+"/decrypted.py")
                            

def main():
	print("Decrypting")
	arch = PyInstArchive("./grabber.exe")
	if arch.open():
		if arch.checkFile():
			if arch.getCArchiveInfo():
				arch.parseTOC()
				arch.extractFiles()
				arch.close()
				decrypt()
	arch.close()


if __name__ == '__main__':
    main()
