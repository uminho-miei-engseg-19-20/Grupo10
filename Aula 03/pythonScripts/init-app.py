import sys
from eVotUM.Cripto import eccblind

def saveToDocument():
    initComponents, pRDashComponents = eccblind.initSigner()
    f= open("initFile.txt","w+")
    data = [initComponents+"\n",pRDashComponents+"\n"]
    for dados in data:
        f.write(dados)
    f.close()

def parseArgs():
    if (len(sys.argv) > 1):
        option = True
        for arg in sys.argv:
            if(arg == "-init"):
                saveToDocument()
                option = False
        if(option):
            print("Invalid Option")
    else:
        main()

def main():
    initComponents, pRDashComponents = eccblind.initSigner()
    print("Output")
    print("pRDashComponents: %s" % pRDashComponents)

if __name__ == "__main__":
    parseArgs()
