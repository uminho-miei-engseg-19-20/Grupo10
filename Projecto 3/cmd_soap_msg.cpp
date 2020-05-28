/*
--------------------------------- CMD SOAP MSG -------------------------------------------

Teste das operações do serviço CMD (versão 1.6 da "CMD - Especificação dos serviços de
Assinatura")

Mensagens CMD SOAP

------------------------------------------------------------------------------------------

Funções que preparam e executam os comandos SOAP do SCMD, nomeadamente:
  + GetCertificate
          (applicationId: xsd:base64Binary, userId: xsd:string)
          -> GetCertificateResult: xsd:string
  + CCMovelSign
        (request: ns2:SignRequest)
        -> CCMovelSignResult: ns2:SignStatus
  + CCMovelMultipleSign
        (request: ns2:MultipleSignRequest, documents: ns2:ArrayOfHashStructure)
        -> CCMovelMultipleSignResult: ns2:SignStatus
  + ValidateOtp
        (code: xsd:string, processId: xsd:string,
            applicationId: xsd:base64Binary)
        -> ValidateOtpResult: ns2:SignResponse

------------------------------------------------------------------------------------------
*/

#include <iostream>
#include <string>
#include <libs/sha256/hl_hashwrapper.h> //Hash SHA256
using namespace std;

