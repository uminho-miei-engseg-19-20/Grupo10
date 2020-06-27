#include <iostream>
#include <iterator>
#include "cmd_soap_msg.h"
#include "argparse.h"
#include "cmd_config.h"
#include "crypto.h"
#include <fstream>
#include <string>
#include <streambuf>
#include <stdlib.h>

using namespace argparse;

int opt(int argc, const char* argv[]) {
	ArgumentParser parser("test_cmd_wsdl", "test");
	parser.enable_help();
	parser.add_argument()
		.names({ "-applicationId APPLICATIONID" })
		.description("	CMD ApplicationId");
	parser.add_argument()
		.names({ "-prod" })
		.description("Use production SCMD service (preproduction SCMD service used by default)");
	parser.add_argument()
		.names({ "-D", "--debug" })
		.description("show debug information");

	auto err = parser.parse(argc, argv);
	if (err) {
		std::cout << err << std::endl;
		return -1;
	}

	if (parser.exists("help")) {
		parser.print_help(0, 1);
		return 0;
	}

	return 0;
}

int parseTEST(int argc, const char* argv[]) {

	ArgumentParser parser("test_cmd_wsdl TestAll [-h] [-applicationId APPLICATIONID] [-prod] [-D] user pin", "test");
	parser.add_argument()
		.names({ "file" })
		.description("file");
	parser.add_argument()
		.names({ "user" })
		.description("user phone number (+XXX NNNNNNNNN)");
	parser.add_argument()
		.names({ "pin" })
		.description("CMD signature PIN");

	parser.print_positional(0, 0, "Automatically test all commands");
	opt(argc, argv);
}

int parseOTP(int argc, const char* argv[]) {

	ArgumentParser parser("test_cmd_wsdl ValidateOtp [-h] [-applicationId APPLICATIONID] [-prod] [-D] user pin", "test");
	parser.add_argument()
		.names({ "OTP" })
		.description("OTP received in your device");
	parser.add_argument()
		.names({ "ProcessId" })
		.description("ProcessID received in the answer of the CCMovelSign/CCMovelMultipleSign command");

	parser.print_positional(0, 0, "Validate OTP");
	opt(argc, argv);
}


int parseMMS(int argc, const char* argv[]) {

	ArgumentParser parser("test_cmd_wsdl CCMovelMultipleSign [-h] [-applicationId APPLICATIONID] [-prod] [-D] user pin", "test");
	parser.add_argument()
		.names({ "user" })
		.description("user phone number (+XXX NNNNNNNNN)");
	parser.add_argument()
		.names({ "pin" })
		.description("CMD signature PIN");

	parser.print_positional(0, 0, "Start multiple signature process");
	opt(argc, argv);
}

int parseMS(int argc, const char* argv[]) {

	ArgumentParser parser("test_cmd_wsdl CCMovelSign [-h] [-applicationId APPLICATIONID] [-prod] [-D] user pin", "test");
	parser.add_argument()
		.names({ "user" })
		.description("user phone number (+XXX NNNNNNNNN)");
	parser.add_argument()
		.names({ "pin" })
		.description("CMD signature PIN");

	parser.print_positional(0, 0, "Start signature process");
	opt(argc, argv);
}

int parseGC(int argc, const char* argv[]) {

	ArgumentParser parser("test_cmd_wsdl GetCertificate [-h] [-applicationId APPLICATIONID] [-prod] [-D] user pin", "test");
	parser.add_argument()
		.names({ "user" })
		.description("user phone number (+XXX NNNNNNNNN)");

	parser.print_positional(0, 0, "Get user certificate");
	opt(argc, argv);
	
}

void testAll(string file, string user, string pin) {
	std::cout << "test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)" << std::endl;
	std::cout << "version: 1.0" << std::endl;
	std::cout << "\n" << "+++ Test All inicializado +++" << "\n" << std::endl;
	std::cout << " 0% ... Leitura de argumentos da linha de comando - file: " << std::endl;
	std::cout << "10% ... A contactar servidor SOAP CMD para operação GetCertificate" << std::endl;
	Soap_Operations soap;
	std::vector<std::string> certificates;
	std::vector<std::string> cns;
	certificates = soap.getcertificates(get_appid(), user);
	if (certificates.empty()) {
		std::cout << "Impossível obter certificado" << std::endl;
		exit (EXIT_FAILURE);
	}
	const char* c1 = certificates[0].c_str();
	const char* c2 = certificates[1].c_str();
	const char* c3 = certificates[2].c_str();
	OpenSSL_add_all_algorithms();
	BIO *bio_mem1 = BIO_new(BIO_s_mem());
	BIO *bio_mem2 = BIO_new(BIO_s_mem());
	BIO *bio_mem3 = BIO_new(BIO_s_mem());
	BIO_puts(bio_mem1, c1);
	BIO_puts(bio_mem2, c2);
	BIO_puts(bio_mem3, c3);
	X509 * x509_1 = PEM_read_bio_X509(bio_mem1, NULL, NULL, NULL);
	X509 * x509_2 = PEM_read_bio_X509(bio_mem2, NULL, NULL, NULL);
	X509 * x509_3 = PEM_read_bio_X509(bio_mem3, NULL, NULL, NULL);
	cns.push_back(parseCN(x509_1));
	cns.push_back(parseCN(x509_2));
	cns.push_back(parseCN(x509_3));
	BIO_free(bio_mem1);
	BIO_free(bio_mem2);
	BIO_free(bio_mem3);
	X509_free(x509_1);
	X509_free(x509_2);
	X509_free(x509_3);
	std::cout << "20% ... Certificado emitido para \"" << cns[0] << "\" pela Entidade de Certificação \"" 
	<< cns[2] << "\" na hierarquia do \"" << cns[1] << "\"" << "\n" << std::flush;
	std::cout << "30% ... Leitura do ficheiro " << file << "\n" << std::flush;
	std::ifstream readFile(file);
	if(!readFile.is_open()) {
		std::cout << "Ficheiro não encontrado." << std::endl;
		exit (EXIT_FAILURE);
	}
	std::string file_content((std::istreambuf_iterator<char>(readFile)), std::istreambuf_iterator<char>());

	std::cout << "40% ... Geração de hash do ficheiro " << file << "\n" << std::flush;
 	std::string hash = sha256(file);
	std::string hashEnc = soap.base64_encode(hash);
	
	std::cout << "50% ... Hash gerada (em base64): " << hashEnc << "\n" << std::flush;
	std::cout << "60% ... A contactar servidor SOAP CMD para operação CCMovelSign" << std::endl;

	// res[0] -> ProcessId ; res[1] -> Code
	std::vector<std::string> res = soap.certccMovelSign(get_appid(), user, pin, hashEnc, file);

	if (res[1] != "200") {
		std::cout << "Erro " << res[1] << ". Valide o PIN introduzido." << "\n" << std::flush;
		exit (EXIT_FAILURE);
	}

	std::cout << "70% ... ProcessID devolvido pela operação CCMovelSign: " << res[0] << "\n" << std::flush;
	std::cout << "80% ... A iniciar operação ValidateOtp" << std::endl;
	std::string otp;
	std::cout << "Introduza o OTP recebido no seu dispositivo: ";
	std::cin >> otp;
	std::cout << "90% ... A contactar servidor SOAP CMD para operação ValidateOtp" << std::endl;
	
	// res2[0] -> Code ; res2[1] -> Message ; res2[2] -> Signature
	std::vector<std::string> res2 = soap.validateotp(get_appid(), otp, res[0]);

	if (res2[0] != "200") {
		std::cout << "Erro " << res2[0] << ". " << res2[1] << "\n" << std::flush;
		exit (EXIT_FAILURE);
	}

	//std::string signEnc = soap.base64_encode(res2[2]);
	auto chrs = res2[2].c_str();
	auto val = reinterpret_cast<unsigned char*>(const_cast<char*>(chrs));
	//const unsigned char *val= (unsigned char *) malloc(res[2].length()+1);
	//strcpy((char *)val,res[2].c_str());
	//unsigned char *cstr = &(res2[2])[0];
	char* base64Text;
	size_t encMessageLength = 256; //ta a bugar
	Base64Encode(val, encMessageLength, &base64Text);
	std::cout << "100% ... Assinatura (em base 64) devolvida pela operação ValidateOtp: " << base64Text << "\n" << std::flush;
	std::cout << "110% ... A validar assinatura ..." << std::endl;

	RSA* rsa;
	BIO *bio_mem4 = BIO_new(BIO_s_mem());
	BIO_puts(bio_mem4, certificates[0].c_str());
	X509 * x509_4 = PEM_read_bio_X509(bio_mem4, NULL, NULL, NULL);
	rsa = getPub(x509_4);
	BIO_free(bio_mem4);
	X509_free(x509_4);

	std::cout << rsa << std::endl;

	bool authentic = verifySignature(rsa, file_content, base64Text);

	std::cout << authentic << std::endl;


}

int main(int argc, const char* argv[]) { 
	ArgumentParser parser("test_cmd_wsdl {GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test} [h] [V]", "Argument parser");
	parser.enable_help();
	parser.add_argument()
		.names({ "-V", "--version" })
		.description("show program version");
	parser.add_argument("\n\nCCMovelDigitalSignature Service:", "\n");
	parser.add_argument("{GetCertificate,gc,CCMovelSign,ms,CCMovelMultipleSign,mms,ValidateOtp,otp,TestAll,test}", "\n");
	parser.add_argument("Signature CMD (SCMD) operations", "\n");
	parser.add_argument()
		.names({ "GetCertificate", "gc"})
		.description("Get user certificate");
	parser.add_argument()
		.names({ "CCMovelSign", "ms" })
		.description("	Start signature process");
	parser.add_argument()
		.names({ "CCMovelMultipleSign", "mms" })
		.description("	Start multiple signature process");
	parser.add_argument()
		.names({ "ValidateOtp", "otp" })
		.description("Validate OTP");
	parser.add_argument()
		.names({ "TestAll", "test" })
		.description("Automatically test all commands");

	
	auto err = parser.parse(argc, argv);
	if (err) {
		std::cout << err << std::endl;
		return -1;
	}

	if (argc > 1) {

		if (!parser.exists("V")) {
			if (argc == 3 && parser.exists("h")) {
				std::string arg = argv[1];
				if (arg == "gc") {
					parseGC(argc, argv);
					return 0;
				}

				else if (arg == "ms") {
					parseMS(argc, argv);
					return 0;
				}

				else if (arg == "mms") {
					parseMMS(argc, argv);
					return 0;
				}

				else if (arg == "otp") {
					parseOTP(argc, argv);
					return 0;
				}

				else if (arg == "test") {
					parseTEST(argc, argv);
					return 0;
				}

				else {
					return 0;
				}
			}

			else if (argc < 3) {
				parser.print_help(0, 0, "test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)");
				return 0;
			}

			else {
				std::string arg = argv[1];
				if (arg == "gc" || arg == "GetCertificate") {
					Soap_Operations soap;
					std::vector<std::string> certificates;
					certificates = soap.getcertificates(get_appid(), argv[2]);
					std::cout << certificates[0] << certificates[1] << certificates[2] << std::endl;

				}
				
				else if(arg == "test" || arg == "TestAll") {
					testAll(argv[2], argv[3], argv[4]);
				}

			
			}
		}

		else if (parser.exists("V")) {
			if (argc <= 3) {
				std::cout << "version: 1.0" << std::endl;
				return 0;
			}
			else {
				return 0;
			}
		}
	}

	return 0;
}