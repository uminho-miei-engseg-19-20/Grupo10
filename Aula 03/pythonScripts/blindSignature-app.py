from eVotUM.Cripto import utils
import sys
from eVotUM.Cripto import eccblind

def allOptions(eccPrivateKeyPath, blindMsg):
    pemKey = utils.readFile(eccPrivateKeyPath)
    print("Input")
    passphrase = raw_input("Passphrase: ")
    initComponents = raw_input("Init components: ")
    errorCode, blindSignature = eccblind.generateBlindSignature(pemKey, passphrase, blindMsg, initComponents)
    showResults(errorCode, blindSignature)

def parseArgs():
    if (len(sys.argv) != 2):
        eccPrivateKeyPath = None
        blindMsg = None
        for arg in range(len(sys.argv)):
            if(sys.argv[arg] == "-key"):
                eccPrivateKeyPath = sys.argv[arg+1]
            if(sys.argv[arg] == "-bmsg"):
                blindMsg = sys.argv[arg+1]
        if(eccPrivateKeyPath is not None and blindMsg is not None):
            allOptions(eccPrivateKeyPath, blindMsg)
        elif(eccPrivateKeyPath is not None):
            main(eccPrivateKeyPath)
        else:
            print("Invalid Argument")
    else:
        eccPrivateKeyPath = sys.argv[1]
        main(eccPrivateKeyPath)

def showResults(errorCode, blindSignature):
    print("Output")
    if (errorCode is None):
        print("Blind signature: %s" % blindSignature)
    elif (errorCode == 1):
        print("Error: it was not possible to retrieve the private key")
    elif (errorCode == 2):
        print("Error: init components are invalid")
    elif (errorCode == 3):
        print("Error: invalid blind message format")

def main(eccPrivateKeyPath):
    pemKey = utils.readFile(eccPrivateKeyPath)
    print("Input")
    passphrase = raw_input("Passphrase: ")
    blindM = raw_input("Blind message: ")
    initComponents = raw_input("Init components: ")
    errorCode, blindSignature = eccblind.generateBlindSignature(pemKey, passphrase, blindM, initComponents)
    showResults(errorCode, blindSignature)

if __name__ == "__main__":
    parseArgs()
