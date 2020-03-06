import sys
from eVotUM.Cripto import eccblind


def blindData(msgData, pRDashComponents):
    errorCode, result = eccblind.blindData(pRDashComponents, msgData)
    showResults(errorCode, result)

def blindDataMSG(msgData):
    print("Input")
    pRDashComponents = raw_input("pRDash components: ")
    errorCode, result = eccblind.blindData(pRDashComponents, msgData)
    showResults(errorCode, result)

def blindDataPRDash(pRDashComponents):
    print("Input")
    data = raw_input("Data: ")
    errorCode, result = eccblind.blindData(pRDashComponents, data)
    showResults(errorCode, result)

def parseArgs():
    if (len(sys.argv) > 1):
        msgData = None
        pRDashComponents = None
        for arg in range(len(sys.argv)):
            if(sys.argv[arg] == "-msg"):
                msgData = sys.argv[arg+1]
            if(sys.argv[arg] == "-RDash"):
                pRDashComponents = sys.argv[arg+1]
        if(msgData is not None and pRDashComponents is not None):
            blindData(msgData, pRDashComponents)
        elif(msgData is not None):
            blindDataMSG(msgData is not None)
        elif(pRDashComponents is not None):
            blindDataPRDash(pRDashComponents)
        else:
            print("Invalid Argument")
    else:
        main()

def showResults(errorCode, result):
    print("Output")
    if (errorCode is None):
        blindComponents, pRComponents, blindM = result
        print("Blind message: %s" % blindM)
        print("Blind components: %s" % blindComponents)
        print("pRComponents: %s" % pRComponents)
        f= open("ofuscaFile.txt","w+")
        data = [blindComponents+"\n",pRComponents+"\n"]
        for dados in data:
            f.write(dados)
        f.close()
    elif (errorCode == 1):
        print("Error: pRDash components are invalid")

def main():
    print("Input")
    data = raw_input("Data: ")
    pRDashComponents = raw_input("pRDash components: ")
    errorCode, result = eccblind.blindData(pRDashComponents, data)
    showResults(errorCode, result)

if __name__ == "__main__":
    parseArgs()
