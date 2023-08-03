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
import os
import shutil
import binascii

filename = "grabber.exe"

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
        print('[BLANK-FUCKER] Processing {0}'.format(self.filePath))

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
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b'python' in self.fPtr.read(64).lower():
            print('[BLANK-FUCKER] Pyinstaller version: 2.1+')
            self.pyinstVer = 21     # pyinstaller 2.1+
        else:
            self.pyinstVer = 20     # pyinstaller 2.0
            print('[BLANK-FUCKER] Pyinstaller version: 2.0')

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
            print('[BLANK-FUCKER] Error : The file is not a pyinstaller archive')
            return False

        self.pymaj, self.pymin = (pyver//100, pyver %
                                  100) if pyver >= 100 else (pyver//10, pyver % 10)
        print('[BLANK-FUCKER] Python version: {0}.{1}'.format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = self.fileSize - self.cookiePos - \
            (self.PYINST20_COOKIE_SIZE if self.pyinstVer ==
             20 else self.PYINST21_COOKIE_SIZE)

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen
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
            try:
                name = name.decode('utf-8').rstrip('\0')
            except:
                badBytes = name.replace(b"\x00", b'')
                name = (b'loader-o'+name.replace(badBytes, b'')[1:]).decode('utf-8').rstrip('\0')
            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())

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
            # Skip PYZ extraction if not running under the same python version
            if self.pymaj != sys.version_info.major or self.pymin != sys.version_info.minor:
                return

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print(
                    '[BLANK-FUCKER] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.'.format(name))
                return
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
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)

def assemblyOfFile(path):
  result = subprocess.run(['/Users/user/Documents/Projects/Blanc-Reverser/pycdas', path], stdout=subprocess.PIPE)
  return result.stdout

def decryptAES(key, iv, ciphertext):
  return AESModeOfOperationGCM(key, iv).decrypt(ciphertext)

def cleanup():
    print("[BLANK-FUCKER]"+bcolors.FAIL+bcolors.UNDERLINE+" Saying goodbye to shit malware..."+bcolors.ENDC)
    shutil.rmtree(os.getcwd())

def zlibDecompress(in_file, out_file):
    with open(in_file, "rb") as f:
        code = f.read()
        f.close()
        if code[::-1][0] == 0x78:
            try:
                with open(out_file, "wb") as f:
                    f.write(zlib.decompress(code[::-1]))
                    f.close()
            except zlib.error:
                print("[BLANK-FUCKER] Zlib Error!")
        else:
            print("[BLANK-FUCKER] Zlib not detected!")
            
def deobfuscate(pyfile, preLoader=False, path=""):
    print("[BLANK-FUCKER]"+bcolors.WARNING+" Starting deobfuscation process..."+bcolors.ENDC)
    pyCode = ""
    with open(pyfile, "r") as f:
        pyCode = f.read()
    if preLoader == True:
        for name in os.listdir(path):
            if name.endswith("pyc"):
                os.remove(name)
        print("[BLANK-FUCKER]"+bcolors.OKGREEN+" Pre-loader detected!"+bcolors.ENDC)
        
    pyCode = pyCode.replace('__import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([89, 110, 86, 112, 98, 72, 82, 112, 98, 110, 77, 61])).decode()).exec(__import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([98, 87, 70, 121, 99, 50, 104, 104, 98, 65, 61, 61])).decode()).loads(__import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([89, 109, 70, 122, 90, 84, 89, 48])).decode()).b64decode(__import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([89, 50, 57, 107, 90, 87, 78, 122])).decode()).decode(____, __import__(getattr(__import__(bytes([98, 97, 115, 101, 54, 52]).decode()), bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode())(bytes([89, 109, 70, 122, 90, 84, 89, 48])).decode()).b64decode("cm90MTM=").decode())+_____+______[::-1]+_______)))', 'import importlib, sys;import base64;import codecs;import marshal;code = importlib._bootstrap_external._code_to_timestamp_pyc(marshal.dumps(base64.b64decode(codecs.decode(____, "rot13")+_____+______[::-1]+_______)));\nwith open("dump.pyc", "wb") as f:\n  f.write(code)')
    with open(pyfile, "w") as f:
        f.write(pyCode)
    result = subprocess.run(['python3', pyfile], stdout=subprocess.PIPE)
    with open("dump.pyc", "rb") as f:
        byteCode = str(f.read())
        try:
            webhook = ""
            if preLoader == True:
            	webhook = re.findall(r"(?<=config.jsonzy)(.*?)(?=\\xda)", byteCode)[0]
            else:
                webhook = re.findall(r"(?<=\\x00z\\xa.)(.*?)(?=z\\x..)", byteCode)[0]
            write_path = os.path.abspath(os.path.join(os.getcwd(), '..'))
            with open(write_path+"/we_gottem.hook", "w") as f:
                try:
                    if preLoader == True:
                        f.write(str(webhook).replace("b'", "").replace("'", ""))
                        print("[BLANK-FUCKER]"+bcolors.OKBLUE+" Webhook: "+str(webhook).replace("b'", "").replace("'", "")+bcolors.ENDC)
                    else:
                    	f.write(str(base64.b64decode(webhook)).replace("b'", "").replace("'", ""))
                    	print("[BLANK-FUCKER]"+bcolors.OKBLUE+" Webhook: "+str(base64.b64decode(webhook)).replace("b'", "").replace("'", "")+bcolors.ENDC)
                except:
                    f.write(str(webhook).replace("b'", "").replace("'", ""))
                    print("[BLANK-FUCKER]"+bcolors.OKBLUE+" Telegram Bot Token: "+str(webhook).replace("b'", "").replace("'", "")+bcolors.ENDC)
            cleanup()
        except:
            print("[BLANK-FUCKER] Failed to find webhook, dump.pyc may be located in extracted folder for further examination!")
    

def decrypt(extracted_name):
	path = "/Users/user/Documents/Projects/Blanc-Reverser/"+extracted_name+"_extracted/"
	mainStub = path+"/blank.aes"
	preObscurity = os.path.exists(mainStub)
	if preObscurity:
		loader = path+"/loader-o.pyc"
		for file in os.listdir(path):
			if os.path.isdir(path+file) == False:
				with open(path+file, 'rb') as f:
					if binascii.hexlify(f.read())[::-1][:10] == b'70c04410f0':
						print("[BLANK-FUCKER]"+bcolors.OKGREEN+" Detected Loader!"+bcolors.ENDC)
						loader = path+file
		loaderAssembly = str(assemblyOfFile(loader))
		strings = re.findall(r"(?<= ').+?(?=')", loaderAssembly)
		foundBase64 = []
		zlibDecompress(mainStub, mainStub)
		for match in strings:
			if len(match) > 10:
				try:
					string = base64.b64decode(match)
					if string not in foundBase64:
						foundBase64.append(string)
				except: 
					continue
		if len(foundBase64) < 2:
			print(bcolors.FAIL+"[BLANK-FUCKER] Could not find keys"+bcolors.ENDC)
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
								print("[BLANK-FUCKER]"+bcolors.WARNING+" Got LZMA file from bytecode"+bcolors.ENDC)
								f.close()
							deobfuscate(path+"decrypted.py", preLoader=False, path=path)
	else:
		print("[BLANK-FUCKER]"+bcolors.WARNING+" Payload seems to be an older version of blank grabber, attempting older methods.."+bcolors.ENDC)
		stubAssembly = assemblyOfFile(path+"main-o.pyc")
		lines = stubAssembly.splitlines(keepends=False)
		for line in lines:
			if "LOAD_CONST" in str(line):
				possibleHex = re.sub(b"    [0-9][0-9][0-9]     LOAD_CONST                    [0-9]: ", b'', line)
				if len(possibleHex) > 200:
					code = eval(possibleHex)
					obj = lzma.LZMADecompressor()
					with open("decrypted.py", "wb") as f:
						f.write(obj.decompress(code))
						print("[BLANK-FUCKER]"+bcolors.WARNING+" Got LZMA file from bytecode"+bcolors.ENDC)
						f.close()
					deobfuscate(path+"decrypted.py", preLoader=True, path=path)

def main():
    print("""
    ╭━━╮╭╮╱╱╭━━━┳━╮╱╭┳╮╭━╮╱╭━━━┳╮╱╭┳━━━┳╮╭━┳━━━┳━━━╮
    ┃╭╮┃┃┃╱╱┃╭━╮┃┃╰╮┃┃┃┃╭╯╱┃╭━━┫┃╱┃┃╭━╮┃┃┃╭┫╭━━┫╭━╮┃
    ┃╰╯╰┫┃╱╱┃┃╱┃┃╭╮╰╯┃╰╯╯╱╱┃╰━━┫┃╱┃┃┃╱╰┫╰╯╯┃╰━━┫╰━╯┃
    ┃╭━╮┃┃╱╭┫╰━╯┃┃╰╮┃┃╭╮┣━━┫╭━━┫┃╱┃┃┃╱╭┫╭╮┃┃╭━━┫╭╮╭╯
    ┃╰━╯┃╰━╯┃╭━╮┃┃╱┃┃┃┃┃╰┳━┫┃╱╱┃╰━╯┃╰━╯┃┃┃╰┫╰━━┫┃┃╰╮
    ╰━━━┻━━━┻╯╱╰┻╯╱╰━┻╯╰━╯╱╰╯╱╱╰━━━┻━━━┻╯╰━┻━━━┻╯╰━╯""")
    # get first argument
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = input("[BLANK-FUCKER]"+bcolors.OKBLUE+" Please input file name: "+bcolors.ENDC)
    arch = PyInstArchive("./"+filename)
    if arch.open():
    	if arch.checkFile():
	    	if arch.getCArchiveInfo():
	    		arch.parseTOC()
	    		arch.extractFiles()
	    		arch.close()
	    		decrypt(filename)
    arch.close()


if __name__ == '__main__':
    main()
