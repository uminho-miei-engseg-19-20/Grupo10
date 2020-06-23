#include "BasicHttpBinding_USCORECCMovelSignature.nsmap" 
#include "soapBasicHttpBinding_USCORECCMovelSignatureProxy.h"
#include "soapH.h"
#include <iostream>
#include <string>

using namespace std;
int main() {
	struct soap soap;
	soap_init(&soap);
	//BasicHttpBinding_USCORECCMovelSignatureProxy BasicHttpBinding_USCORECCMovelSignature;
	_ns3__GetCertificate* cla;
	xsd__base64Binary* api;
	std::string *numero = "+351 914307721";
	char* code = "b826359c-06f8-425e-8ec3-50a97a418916";
	api->id = code;
	//numero = "+351 914307721";
	cla->applicationId = api;
	cla->userId = numero;
	const std::string GetCertificateResult;
	//_ns3__GetCertificateResponse ce;
	if (soap_read___ns1__GetCertificate(&soap, cla) == SOAP_OK)
		std::cout << "ola" << std::endl;
	else
		soap_print_fault(&soap, stderr);

	soap_destroy(&soap);
	soap_end(&soap);
	soap_done(&soap);

	return 0;

	//if (BasicHttpBinding_USCORECCMovelSignature.GetCertificate(cla, ce) == SOAP_OK)
	//	std::cout << "ola" << std::endl;
	//else
	//	BasicHttpBinding_USCORECCMovelSignature.soap_stream_fault(std::cerr);
	//BasicHttpBinding_USCORECCMovelSignature.destroy();
}