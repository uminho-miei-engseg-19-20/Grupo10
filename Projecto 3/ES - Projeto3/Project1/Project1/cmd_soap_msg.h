#ifndef CMD_SOAP_MSG
#define CMD_SOAP_MSG


#include <stdio.h>
#include <string>
#include <vector>
#include <iostream>
#include <stdlib.h>
#include <array>

using namespace std;
static const std::string b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


class Soap_Operations {
	public:
		std::string stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl";
		typedef unsigned char uchar;
		static std::string base64_encode(const std::string &in) {
			std::string out;

			int val = 0, valb = -6;
			for (uchar c : in) {
				val = (val << 8) + c;
				valb += 8;
				while (valb >= 0) {
					out.push_back(b[(val >> valb) & 0x3F]);
					valb -= 6;
				}
			}
			if (valb > -6) out.push_back(b[((val << 8) >> (valb + 8)) & 0x3F]);
			while (out.size() % 4) out.push_back('=');
			return out;
		}

		void replaceAll(std::string& str, const std::string& from, const std::string& to) {
			if (from.empty())
				return;
			size_t start_pos = 0;
			while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
				str.replace(start_pos, from.length(), to);
				start_pos += to.length(); 
			}
		}
		

		vector<string> split_certificate(string result, string delimiter) {
			std::string last;
			std::string value = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><GetCertificateResponse xmlns=\"http://Ama.Authentication.Service/\"><GetCertificateResult>";
			std::vector<std::string> add;
			size_t pos = 0;
			std::string token;
			while ((pos = result.find(delimiter)) != std::string::npos) {
				token = result.substr(0, pos);
				replaceAll(token, value, "");
				replaceAll(token, "&#xD;", "");
				//std::cout << token << std::endl;
				add.push_back(token);
				result.erase(0, pos + delimiter.length());
			}
			last = delimiter.append(result);
			replaceAll(last, "&#xD;", "");
			replaceAll(last, "</GetCertificateResult></GetCertificateResponse></s:Body></s:Envelope>", "");
			add.push_back(last);
			add.erase(add.begin());
			return add;
		}


		vector<string> getcertificates(string applicationId, string userId) {
			std::string xml;
			std::string SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/GetCertificate";
			std::string encoded = base64_encode(applicationId);
			std::string curl;
			std::string result;
			std::string begin = "-----BEGIN CERTIFICATE-----";
			std::string begin2 = "-----BEGIN CERTIFICATE-----";
			vector<string> certificates;
			xml.append("\"<soapenv:Envelope xmlns:soapenv=\\\"http://schemas.xmlsoap.org/soap/envelope/\\\">");
			xml.append("   <soapenv:Header/> <soapenv:Body>");
			xml.append("<GetCertificate xmlns=\\\"http://Ama.Authentication.Service/\\\">");
			xml.append("<applicationId>");
			xml.append(encoded);
			xml.append("</applicationId>");
			xml.append("<userId>");
			xml.append(userId);
			xml.append("</userId></GetCertificate></soapenv:Body></soapenv:Envelope>\"");

			curl.append("curl --header \"Content-Type: text/xml\" --header \"SOAPAction: ");
			curl.append(SOAP_ACTION);
			curl.append("\"");
			curl.append(" --data ");
			curl.append(xml);
			curl.append(" ");
			curl.append(stringUrl);
			result = exec(curl.c_str());

			certificates = split_certificate(result, begin);

			certificates[0] = begin.append(certificates[0]);
			certificates[1] = begin2.append(certificates[1]);

			return certificates;
		}

		string getRows(string result, string init, string end) {
			unsigned first = result.find(init);
			unsigned last = result.find(end);
			string resultFinal = result.substr ((first)+init.length(),(last-first+1)-end.length());
			return resultFinal;
		}

		vector<string> certccMovelSign(string applicationId, string userId, string pin, string docHash, string docName) {
			std::string xml;
			std::string SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/CCMovelSign";
			std::string encoded = base64_encode(applicationId);
			std::string curl;
			std::string result;
			vector<string> ccmovel;
			xml.append("\"<soapenv:Envelope xmlns:soapenv=\\\"http://schemas.xmlsoap.org/soap/envelope/\\\">");
			xml.append("   <soapenv:Body>");
			xml.append("<CCMovelSign xmlns=\\\"http://Ama.Authentication.Service/\\\">");
			xml.append("<request xmlns:a=\\\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\\\" xmlns:i=\\\"http://www.w3.org/2001/XMLSchema-instance\\\">");
			xml.append("<a:ApplicationId>");
			xml.append(encoded);
			xml.append("</a:ApplicationId>");
			xml.append("<a:DocName>");
			xml.append(docName);
			xml.append("</a:DocName>");
			xml.append("<a:Hash>");
			xml.append(docHash);
			xml.append("</a:Hash>");
			xml.append("<a:Pin>");
			xml.append(pin);
			xml.append("</a:Pin>");
			xml.append("<a:UserId>");
			xml.append(userId);
			xml.append("</a:UserId></request></CCMovelSign></soapenv:Body></soapenv:Envelope>\"");

			curl.append("curl --header \"Content-Type: text/xml\" --header \"SOAPAction: ");
			curl.append(SOAP_ACTION);
			curl.append("\"");
			curl.append(" --data ");
			curl.append(xml);
			curl.append(" ");
			curl.append(stringUrl);
			result = exec(curl.c_str());
			
			string process = getRows(result, "<a:ProcessId>", "</a:ProcessId>");
			ccmovel.push_back(process);

			string code = getRows(result, "<a:Code>", "</a:Code>");
			ccmovel.push_back(code);

			return ccmovel;
		}

		vector<string> validateotp(string applicationId, string otp, string processId) {
			std::string xml;
			std::string SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/ValidateOtp";
			std::string encoded = base64_encode(applicationId);
			std::string curl;
			std::string result;
			vector<string> validateOTP;
			xml.append("\"<soapenv:Envelope xmlns:soapenv=\\\"http://schemas.xmlsoap.org/soap/envelope/\\\" xmlns:ama=\\\"http://Ama.Authentication.Service/\\\">");
			xml.append("   <soapenv:Body>");
			xml.append("<ama:ValidateOtp>");
			xml.append("<ama:code>");
			xml.append(otp);
			xml.append("</ama:code>");
			xml.append("<ama:processId>");
			xml.append(processId);
			xml.append("</ama:processId>");
			xml.append("<ama:applicationId>");
			xml.append(encoded);
			xml.append("</ama:applicationId></ama:ValidateOtp></soapenv:Body></soapenv:Envelope>\"");

			curl.append("curl --header \"Content-Type: text/xml\" --header \"SOAPAction: ");
			curl.append(SOAP_ACTION);
			curl.append("\"");
			curl.append(" --data ");
			curl.append(xml);
			curl.append(" ");
			curl.append(stringUrl);
			result = exec(curl.c_str());

			string code = getRows(result, "<a:Code>", "</a:Code>");
			validateOTP.push_back(code);

			string message = getRows(result, "<a:Message>", "</a:Message>");
			validateOTP.push_back(message);

			string signature = getRows(result, "<a:Signature>", "</a:Signature>");
			validateOTP.push_back(signature);

			return validateOTP;
		}

		std::string getPub(std::string certificate) {
			std::string result = "";
			std::string aux1 = "openssl x509 -pubkey -noout -in /dev/sdin <<< \'";
			std::string aux2 = "\' > stdout";
			std::string aux3 = aux1.append(certificate);
			std::string command = aux3.append(aux2);
			std::cout << command << std::endl;
			result = exec(command.c_str());
			return result;
		}

		std::string exec(const char* cmd) {
			std::array<char, 128> buffer;
			std::string result;

			auto pipe = popen(cmd, "r"); // get rid of shared_ptr

			if (!pipe) throw std::runtime_error("popen() failed!");

			while (!feof(pipe)) {
				if (fgets(buffer.data(), 128, pipe) != nullptr)
					result += buffer.data();
			}

			auto rc = pclose(pipe);

			if (rc == EXIT_SUCCESS) { // == 0

			}
			else if (rc == EXIT_FAILURE) {  // EXIT_FAILURE is not used by all programs, maybe needs some adaptation.

			}
			return result;
		}

};


#endif


