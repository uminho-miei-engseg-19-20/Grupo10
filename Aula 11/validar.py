import datetime
import string

def validateValue(value):
    if not value.strip().replace('-', '').replace('+', '').replace('.', '').isdigit():
        print("Esse número não é válido!")
        return False
    if "." in str(value):
        if len(str(value).split('.')[-1]) != 2:
            print("Esse número não é válido!")
            return False
    try:
        float(value)
    except ValueError:
        print("Esse número não é válido!")
        return False
    return True


def validateDate(date):
    try:
        datetime.datetime.strptime(date, '%d-%m-%Y')
    except ValueError:
        print("Formato de data incorreto. Formato (Dia-Mês-Ano).")
        return False
    return True


def validateName(name):
    new_name = str(name).split(' ')
    for names in new_name:
        if names.isalpha() and names[0].isupper():
            return True
        else:
            print("Inválido!")
            return False


def validateNIF(nif):
    maxDigits = 9
    total = 0
    if not nif.isdigit() or len(nif) != maxDigits:
        print("NIF inválido!")
        return False
    total = sum([int(digit) * (maxDigits - position)
                 for position, digit in enumerate(nif)])
    rest = total % 11
    if nif[-1] == '0' and rest == 1:
        rest = (total + 10) % 11
    if rest == 0:
        return True
    else:
        print("NIF inválido!")
        return False


def getNumberFromChar(letter):
    charDict = {
        "0": "0",
        "1": "1",
        "2": "2",
        "3": "3",
        "4": "4",
        "5": "5",
        "6": "6",
        "7": "7",
        "8": "8",
        "9": "9",
        "A": "10",
        "B": "11",
        "C": "12",
        "D": "13",
        "E": "14",
        "F": "15",
        "G": "16",
        "H": "17",
        "I": "18",
        "J": "19",
        "K": "20",
        "L": "21",
        "M": "22",
        "N": "23",
        "O": "24",
        "P": "25",
        "Q": "26",
        "R": "27",
        "S": "28",
        "T": "29",
        "U": "30",
        "V": "31",
        "W": "32",
        "X": "33",
        "Y": "34",
        "Z": "35",
    }
    return int(charDict[letter])


def validateCC(cc):
    cc = cc.replace(" ", "")
    upperString = cc.upper()
    total = 0
    secondDigit = 0

    if len(cc) != 12:
        print("Número de cartão de cidadão inválido!")
        return 0

    for i in range(len(cc) - 1, -1, -1):
        valor = getNumberFromChar(upperString[i])
        if secondDigit == 1:
            valor = valor * 2
            if valor > 9:
                valor = valor - 9
        total = total + valor
        secondDigit = 1 if secondDigit == 0 else 0

    if total % 10 == 0:
        return True
    else:
        print("Número de cartão de cidadão inválido!")
        return False


def validateCreditCard(creditCard):
    total = 0

    creditCard = creditCard.replace(" ", "")

    if not creditCard.isdigit() or 7 > len(creditCard) or len(creditCard) > 19:
        print("Cartão de crédito inválido!")
        return False

    for i, d in enumerate(int(t) for t in creditCard):
        if i%2 == len(creditCard) % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    if total % 10 == 0:
        return True
    else:
        print("Cartão de crédito inválido!")
        return False


def validateDateCreditCard(date):
    month, year = date.split("-")
    if int(month) > 0 and int(month) < 13 and len(year) == 4:
        maxDay = (datetime.date(int(year), int(month)+1, 1) - datetime.date(int(year), int(month), 1)).days
    else:
        print("Formato de data errado!")
        return False
    if datetime.datetime(int(year), int(month), int(maxDay)) <= datetime.datetime.now():
        print("Validade do cartão de crédito inválida!")
        return False
    else:
        return True

def validateCVCCVV(cvccvv):
    if cvccvv.isdigit() and len(cvccvv) == 4:
        return True
    else:
        print("CVC/CVV inválido!")
        return False


def main():
    while True:
        print("\nBem-Vindo ao registo para validação de input.\n")
        print("\n_______________________________________________________\n")

        value = input("\nValor a pagar: ")
        while not validateValue(value):
            value = input("\nValor a pagar: ")
        datenasc = input("\nData de nascimento (Dia-Mês-Ano): ")
        while not validateDate(datenasc):
            datenasc = input("\nData de nascimento (Dia-Mês-Ano): ")
        name = input("\nNome: ")
        while not validateName(name):
            name = input("\nNome: ")
        nif = input("\nNúmero de identificação fiscal: ")
        while not validateNIF(nif):
            nif = input("\nNúmero de identificação fiscal: ")
        nic = input("\nNúmero de identificação de cidadão: ")
        while not validateCC(nic):
            nic = input("\nNúmero de identificação de cidadão: ")
        ncc = input("\nNúmero do cartão de crédito: ")
        while not validateCreditCard(ncc):
            ncc = input("\nNúmero do cartão de crédito: ")
        validate = input("\nData de validade do cartão de crédito (Mês-Ano): ")
        while not validateDateCreditCard(validate):
            validate = input("\nData de validade do cartão de crédito (Mês-Ano): ")
        cvccvv = input("\nNúmero CVC/CVV: ")
        while not validateCVCCVV(cvccvv):
            cvccvv = input("\nNúmero CVC/CVV: ")
        break
    print("\nRegisto efetuado com sucesso!\n")

if __name__ == "__main__":
    main()
  