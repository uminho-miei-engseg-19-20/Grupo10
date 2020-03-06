import sys
from eVotUM.Cripto import eccblind

def unblindData(assData, pRDashComponents):
    print("Input")
    blindComponents = raw_input("Blind components: ")
    errorCode, signature = eccblind.unblindSignature(assData, pRDashComponents, blindComponents)
    showResults(errorCode, signature)

def unblindDataAssData(assData):
    print("Input")
    blindComponents = raw_input("Blind components: ")
    pRDashComponents = raw_input("pRDash components: ")
    errorCode, signature = eccblind.unblindSignature(assData, pRDashComponents, blindComponents)
    showResults(errorCode, signature)

def unblindDataPRDash(pRDashComponents):
    print("Input")
    blindSignature = raw_input("Blind signature: ")
    blindComponents = raw_input("Blind components: ")
    errorCode, signature = eccblind.unblindSignature(blindSignature, pRDashComponents, blindComponents)
    showResults(errorCode, signature)

def parseArgs():
    if (len(sys.argv) > 1):
        assData = None
        pRDashComponents = None
        for arg in range(len(sys.argv)):
            if(sys.argv[arg] == "-s"):
                assData = sys.argv[arg+1]
            if(sys.argv[arg] == "-RDash"):
                pRDashComponents = sys.argv[arg+1]
        if(assData is not None and pRDashComponents is not None):
            unblindData(assData, pRDashComponents)
        elif(ass is not None):
            unblindDataAssData(assData)
        elif(pRDashComponents is not None):
            unblindDataPRDash(pRDashComponents)
        else:
            print("Invalid Argument")
    else:
        main()

def showResults(errorCode, signature):
    print("Output")
    if (errorCode is None):
        print("Signature: %s" % signature)
    elif (errorCode == 1):
        print("Error: pRDash components are invalid")
    elif (errorCode == 2):
        print("Error: blind components are invalid")
    elif (errorCode == 3):
        print("Error: invalid blind signature format")

def main():
    print("Input")
    blindSignature = raw_input("Blind signature: ")
    blindComponents = raw_input("Blind components: ")
    pRDashComponents = raw_input("pRDash components: ")
    errorCode, signature = eccblind.unblindSignature(blindSignature, pRDashComponents, blindComponents)
    showResults(errorCode, signature)

if __name__ == "__main__":
    parseArgs()
