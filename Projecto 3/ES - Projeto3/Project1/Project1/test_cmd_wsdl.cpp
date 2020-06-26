#include <iostream>
#include <iterator>
#include "cmd_soap_msg.h"
#include "argparse.h"
#include "cmd_config.h"

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