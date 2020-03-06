import sys
from eVotUM.Cripto import eccblind
from eVotUM.Cripto import utils

def allArgs(data,cert,sDash,files):
    pemPublicKey = utils.readFile(cert)
    pRComponents = None
    blindComponents = None
    f=open(files, "r")
    f = f.readlines()
    cont=0
    for x in f:
        if(cont==0):
            blindComponents=x.rstrip()
        if(cont==1):
            pRComponents=x.rstrip()
        cont=+1
    errorCode, validSignature = eccblind.verifySignature(pemPublicKey, sDash, blindComponents, pRComponents, data)
    showResults(errorCode, validSignature)

def parseArgs():
    if (len(sys.argv) != 2):
        eccPrivateKeyPath=None
        blindMsg=None
        sDash=None
        files=None
        for arg in range(len(sys.argv)):
            if(sys.argv[arg] == "-cert"):
                eccPrivateKeyPath = sys.argv[arg+1]
            if(sys.argv[arg] == "-msg"):
                blindMsg = sys.argv[arg+1]
            if(sys.argv[arg] == "-sDash"):
                sDash = sys.argv[arg+1]
            if(sys.argv[arg] == "-f"):
                files = sys.argv[arg+1]
        if(eccPrivateKeyPath is not None and blindMsg is not None and sDash is not None and files is not None):
            allArgs(blindMsg,eccPrivateKeyPath,sDash,files)
        else:
            print("Invalid Arguments")
    else:
        eccPublicKeyPath = sys.argv[1]
        main(eccPublicKeyPath)

def showResults(errorCode, validSignature):
    print("Output")
    if (errorCode is None):
        if (validSignature):
            print("Valid signature")
        else:
            print("Invalid signature")
    elif (errorCode == 1):
        print("Error: it was not possible to retrieve the public key")
    elif (errorCode == 2):
        print("Error: pR components are invalid")
    elif (errorCode == 3):
        print("Error: blind components are invalid")
    elif (errorCode == 4):
        print("Error: invalid signature format")

def main(eccPublicKeyPath):
    pemPublicKey = utils.readFile(eccPublicKeyPath)
    print("Input")
    data = raw_input("Original data: ")
    signature = raw_input("Signature: ")
    blindComponents = raw_input("Blind components: ")
    pRComponents = raw_input("pR components: ")
    errorCode, validSignature = eccblind.verifySignature(pemPublicKey, signature, blindComponents, pRComponents, data)
    showResults(errorCode, validSignature)

if __name__ == "__main__":
    parseArgs()
