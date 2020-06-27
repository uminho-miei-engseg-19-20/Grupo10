#ifndef CRYPTO_AUX
#define CRYPTO_AUX

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <fstream>
#include <iomanip>


using std::cout;
using std::endl;
using std::stringstream;
using std::map;
using std::vector;
using std::string;

//----------------------------------------------------------------------
string thumbprint(X509* x509)
{
	static const char hexbytes[] = "0123456789ABCDEF";
	unsigned int md_size;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD * digest = EVP_get_digestbyname("sha1");
	X509_digest(x509, digest, md, &md_size);
	stringstream ashex;
	for (int pos = 0; pos < md_size; pos++)
	{
		ashex << hexbytes[(md[pos] & 0xf0) >> 4];
		ashex << hexbytes[(md[pos] & 0x0f) >> 0];
	}
	return ashex.str();
}
//----------------------------------------------------------------------
int certversion(X509* x509)
{
	return X509_get_version(x509) + 1;
}
//----------------------------------------------------------------------
string pem(X509* x509)
{
	BIO * bio_out = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio_out, x509);
	BUF_MEM *bio_buf;
	BIO_get_mem_ptr(bio_out, &bio_buf);
	string pem = string(bio_buf->data, bio_buf->length);
	BIO_free(bio_out);
	return pem;
}
//----------------------------------------------------------------------
void _asn1dateparse(const ASN1_TIME *time, int& year, int& month, int& day, int& hour, int& minute, int& second)
{
	const char* str = (const char*)time->data;
	size_t i = 0;
	if (time->type == V_ASN1_UTCTIME) {/* two digit year */
		year = (str[i++] - '0') * 10;
		year += (str[i++] - '0');
		year += (year < 70 ? 2000 : 1900);
	}
	else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
		year = (str[i++] - '0') * 1000;
		year += (str[i++] - '0') * 100;
		year += (str[i++] - '0') * 10;
		year += (str[i++] - '0');
	}
	month = (str[i++] - '0') * 10;
	month += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
	day = (str[i++] - '0') * 10;
	day += (str[i++] - '0');
	hour = (str[i++] - '0') * 10;
	hour += (str[i++] - '0');
	minute = (str[i++] - '0') * 10;
	minute += (str[i++] - '0');
	second = (str[i++] - '0') * 10;
	second += (str[i++] - '0');
}
//----------------------------------------------------------------------
string _asn1int(ASN1_INTEGER *bs)
{
	static const char hexbytes[] = "0123456789ABCDEF";
	stringstream ashex;
	for (int i = 0; i < bs->length; i++)
	{
		ashex << hexbytes[(bs->data[i] & 0xf0) >> 4];
		ashex << hexbytes[(bs->data[i] & 0x0f) >> 0];
	}
	return ashex.str();
}
//----------------------------------------------------------------------
string _asn1string(ASN1_STRING *d)
{
	string asn1_string;
	if (ASN1_STRING_type(d) != V_ASN1_UTF8STRING) {
		unsigned char *utf8;
		int length = ASN1_STRING_to_UTF8(&utf8, d);
		asn1_string = string((char*)utf8, length);
		OPENSSL_free(utf8);
	}
	else {
		asn1_string = string((char*)ASN1_STRING_data(d), ASN1_STRING_length(d));
	}
	return asn1_string;
}
//----------------------------------------------------------------------
string _subject_as_line(X509_NAME *subj_or_issuer)
{
	BIO * bio_out = BIO_new(BIO_s_mem());
	X509_NAME_print(bio_out, subj_or_issuer, 0);
	BUF_MEM *bio_buf;
	BIO_get_mem_ptr(bio_out, &bio_buf);
	string issuer = string(bio_buf->data, bio_buf->length);
	BIO_free(bio_out);
	return issuer;
}
//----------------------------------------------------------------------
std::map<string, string> _subject_as_map(X509_NAME *subj_or_issuer)
{
	std::map<string, string> m;
	for (int i = 0; i < X509_NAME_entry_count(subj_or_issuer); i++) {
		X509_NAME_ENTRY *e = X509_NAME_get_entry(subj_or_issuer, i);
		ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
		ASN1_OBJECT *o = X509_NAME_ENTRY_get_object(e);
		const char* key_name = OBJ_nid2sn(OBJ_obj2nid(o));
		m[key_name] = _asn1string(d);
	}
	return m;
}
//----------------------------------------------------------------------
string issuer_one_line(X509* x509)
{
	return _subject_as_line(X509_get_issuer_name(x509));
}
//----------------------------------------------------------------------
string subject_one_line(X509* x509)
{	
	std::string subject = _subject_as_line(X509_get_subject_name(x509));
	size_t position = subject.find("CN=");  
	std::string CN = subject.substr(position+3); 
	return CN;
}
//----------------------------------------------------------------------
std::map<string, string> subject(X509* x509)
{
	return _subject_as_map(X509_get_subject_name(x509));
}
//----------------------------------------------------------------------
std::map<string, string> issuer(X509* x509)
{
	return _subject_as_map(X509_get_issuer_name(x509));
}
//----------------------------------------------------------------------
string serial(X509* x509)
{
	return _asn1int(X509_get_serialNumber(x509));
}
//----------------------------------------------------------------------
//string signature_algorithm(X509 *x509)
//{
//	int sig_nid = OBJ_obj2nid((x509)->sig_alg->algorithm);
//	return string(OBJ_nid2ln(sig_nid));
//}
//----------------------------------------------------------------------
string public_key_type(X509 *x509)
{
	EVP_PKEY *pkey = X509_get_pubkey(x509);
	//int key_type = EVP_PKEY_type(pkey->type);
	EVP_PKEY_free(pkey);
	//if (key_type == EVP_PKEY_RSA) return "rsa";
	//if (key_type == EVP_PKEY_DSA) return "dsa";
	//if (key_type == EVP_PKEY_DH)  return "dh";
	//if (key_type == EVP_PKEY_EC)  return "ecc";
	return "";
}
//----------------------------------------------------------------------
int public_key_size(X509 *x509)
{
	EVP_PKEY *pkey = X509_get_pubkey(x509);
	//int key_type = EVP_PKEY_type(pkey->type);
	int keysize = -1; //or in bytes, RSA_size() DSA_size(), DH_size(), ECDSA_size();
	//keysize = key_type == EVP_PKEY_RSA && pkey->pkey.rsa->n ? BN_num_bits(pkey->pkey.rsa->n) : keysize;
	//keysize = key_type == EVP_PKEY_DSA && pkey->pkey.dsa->p ? BN_num_bits(pkey->pkey.dsa->p) : keysize;
	//keysize = key_type == EVP_PKEY_DH && pkey->pkey.dh->p ? BN_num_bits(pkey->pkey.dh->p) : keysize;
	//keysize = key_type == EVP_PKEY_EC ? EC_GROUP_get_degree(EC_KEY_get0_group(pkey->pkey.ec)) : keysize;
	EVP_PKEY_free(pkey);
	return keysize;
}
//----------------------------------------------------------------------
/*
string public_key_ec_curve_name(X509 *x509)
{
	EVP_PKEY *pkey = X509_get_pubkey(x509);
	int key_type = EVP_PKEY_type(pkey->type);
	if (key_type == EVP_PKEY_EC)
	{
		const EC_GROUP *group = EC_KEY_get0_group(pkey->pkey.ec);
		int name = (group != NULL) ? EC_GROUP_get_curve_name(group) : 0;
		return name ? OBJ_nid2sn(name) : "";
	}
	return "";
}
*/
//----------------------------------------------------------------------
string asn1datetime_isodatetime(const ASN1_TIME *tm)
{
	int year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0;
	_asn1dateparse(tm, year, month, day, hour, min, sec);

	char buf[25] = "";
	snprintf(buf, sizeof(buf) - 1, "%04d-%02d-%02d %02d:%02d:%02d GMT", year, month, day, hour, min, sec);
	return string(buf);
}
//----------------------------------------------------------------------
string asn1date_isodate(const ASN1_TIME *tm)
{
	int year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0;
	_asn1dateparse(tm, year, month, day, hour, min, sec);

	char buf[25] = "";
	snprintf(buf, sizeof(buf) - 1, "%04d-%02d-%02d", year, month, day);
	return string(buf);
}
//----------------------------------------------------------------------
vector<string> subject_alt_names(X509 *x509)
{
	vector<string> list;
	GENERAL_NAMES* subjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	for (int i = 0; i < sk_GENERAL_NAME_num(subjectAltNames); i++)
	{
		GENERAL_NAME* gen = sk_GENERAL_NAME_value(subjectAltNames, i);
		if (gen->type == GEN_URI || gen->type == GEN_DNS || gen->type == GEN_EMAIL)
		{
			ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
			string san = string((char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str));
			list.push_back(san);
		}
		else if (gen->type == GEN_IPADD)
		{
			unsigned char *p = gen->d.ip->data;
			if (gen->d.ip->length == 4)
			{
				stringstream ip;
				ip << (int)p[0] << '.' << (int)p[1] << '.' << (int)p[2] << '.' << (int)p[3];
				list.push_back(ip.str());
			}
			else //if(gen->d.ip->length == 16) //ipv6?
			{
				//std::cerr << "Not implemented: parse sans ("<< __FILE__ << ":" << __LINE__ << ")" << endl;
			}
		}
		else
		{
			//std::cerr << "Not implemented: parse sans ("<< __FILE__ << ":" << __LINE__ << ")" << endl;
		}
	}
	GENERAL_NAMES_free(subjectAltNames);
	return list;
}
//----------------------------------------------------------------------
vector<string> ocsp_urls(X509 *x509)
{
	vector<string> list;
	STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(x509);
	for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++)
	{
		list.push_back(string(sk_OPENSSL_STRING_value(ocsp_list, j)));
	}
	X509_email_free(ocsp_list);
	return list;
}
//----------------------------------------------------------------------
vector<string> crl_urls(X509 *x509)
{
	vector<string> list;
	int nid = NID_crl_distribution_points;
	STACK_OF(DIST_POINT) * dist_points = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(x509, nid, NULL, NULL);
	for (int j = 0; j < sk_DIST_POINT_num(dist_points); j++)
	{
		DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
		DIST_POINT_NAME    *distpoint = dp->distpoint;
		if (distpoint->type == 0)//fullname GENERALIZEDNAME
		{
			for (int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++)
			{
				GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
				ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
				list.push_back(string((char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str)));
			}
		}
		else if (distpoint->type == 1)//relativename X509NAME
		{
			STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
			for (int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++)
			{
				X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, k);
				ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
				list.push_back(string((char*)ASN1_STRING_data(d), ASN1_STRING_length(d)));
			}
		}
	}
	CRL_DIST_POINTS_free(dist_points);
	return list;
}
//----------------------------------------------------------------------
void parseCert1(X509* x509)
{
	cout << "--------------------" << endl;
	BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	//PEM_write_bio_X509(bio_out, x509);//STD OUT the PEM
	X509_print(bio_out, x509);//STD OUT the details
	//X509_print_ex(bio_out, x509, XN_FLAG_COMPAT, X509_FLAG_COMPAT);//STD OUT the details
	BIO_free(bio_out);
}
//----------------------------------------------------------------------
/*
void parseCert2(X509* x509)
{
	cout << "--------------------" << endl;
	BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	long l = X509_get_version(x509);
	BIO_printf(bio_out, "Version: %ld\n", l + 1);

	ASN1_INTEGER *bs = X509_get_serialNumber(x509);
	BIO_printf(bio_out, "Serial: ");
	for (int i = 0; i < bs->length; i++) {
		BIO_printf(bio_out, "%02x", bs->data[i]);
	}
	BIO_printf(bio_out, "\n");

	X509_signature_print(bio_out, x509->sig_alg, NULL);

	BIO_printf(bio_out, "Issuer: ");
	X509_NAME_print(bio_out, X509_get_issuer_name(x509), 0);
	BIO_printf(bio_out, "\n");

	BIO_printf(bio_out, "Valid From: ");
	ASN1_TIME_print(bio_out, X509_get_notBefore(x509));
	BIO_printf(bio_out, "\n");

	BIO_printf(bio_out, "Valid Until: ");
	ASN1_TIME_print(bio_out, X509_get_notAfter(x509));
	BIO_printf(bio_out, "\n");

	BIO_printf(bio_out, "Subject: ");
	X509_NAME_print(bio_out, X509_get_subject_name(x509), 0);
	BIO_printf(bio_out, "\n");

	EVP_PKEY *pkey = X509_get_pubkey(x509);
	EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
	EVP_PKEY_free(pkey);

	X509_CINF *ci = x509->cert_info;
	X509V3_extensions_print(bio_out, (char*)"X509v3 extensions", ci->extensions, X509_FLAG_COMPAT, 0);

	X509_signature_print(bio_out, x509->sig_alg, x509->signature);
	BIO_free(bio_out);
}
*/



//----------------------------------------------------------------------
std::string parseCN(X509* x509) {
	std::string cn;
	map<string, string> sfields = subject(x509);
	for (map<string, string>::iterator i = sfields.begin(), ix = sfields.end(); i != ix; i++) {
		if (i->first == "CN") {
			cn = i->second;
		}
	}
	return cn;
}

string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}


bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic) {
  MsgHashLen = 256;							 
  *Authentic = false;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
      return false;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
      return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  std::cout << MsgHash << " " << MsgHashLen << "\n" << std::flush;
  std::cout << AuthStatus << std::endl;
  if (AuthStatus==1) {
    *Authentic = true;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else if(AuthStatus==0){
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else{
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return false;
  }
}

size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  *base64Text=(*bufferPtr).data;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

bool verifySignature(RSA* publicRSA, std::string plainText, char* signatureBase64) {
  unsigned char* encMessage;
  size_t encMessageLength;
  bool authentic;
  Base64Decode(signatureBase64, &encMessage, &encMessageLength);
  bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
  return result & authentic;
}



RSA* getPub(X509* x509) {
	X509* cert;
	//BIO *certbio = NULL;
	//BIO *outbio = NULL;
	//int ret;
	//certbio = BIO_new(BIO_s_file());
	//outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
	//ret = BIO_read_filename(certbio, x509);
	//char * string = (char*)malloc(600*sizeof(char)); //bigger than I need
	//setbuf(stdout, string);
	//uint32_t size = 0;
	//int rc;
	EVP_PKEY* pubkey;
	RSA* rsa;
	//cert = d2i_x509(NULL, certificateDataBytes, length);
	pubkey = X509_get_pubkey(x509);
	//std::cout << outbio << std::endl;
	//BIO_printf(outbio, "%d bit RSA Key\n\n", EVP_PKEY_bits(pubkey));
	//PEM_read_bio_PUBKEY(outbio, pubkey, NULL, NULL);
	//char* key1;
	//key = X509_get_X509_PUBKEY(x509);
	//std::cout << key << std::endl;
	//BIO *bio_mem1 = BIO_new(BIO_s_mem());
	//pubkey = PEM_read_bio_PUBKEY(bio_mem1, &pubkey, NULL, NULL);
	//BIO_gets(bio_mem1, key1, 300);
	rsa = EVP_PKEY_get1_RSA(pubkey);
	//setbuf(stdout, NULL);
	//PEM_write_bio_PUBKEY(outbio,pubkey);
	//std::cout << "\n" << std::endl;
	//std::cout << string << std::endl;
	//std::cout << key1 << std::endl;
	//PEM_write_bio_PUBKEY(outbio, pubkey) >> key;	//
	//RSA_print_fp(stdout, rsa, 0);
	//bio_to_
	//RSA_free(rsa);
	//std::cout << rsa << std::endl;
	EVP_PKEY_free(pubkey);
	return rsa;
}

/*
void parseCert3(X509* x509)
{
	std::vector<std::string> cns;
	//cout << "--------------------" << endl;
	//cout << pem(x509) << endl;
	//cout << "Thumbprint: " << thumbprint(x509) << endl;
	//cout << "Version: " << certversion(x509) << endl;
	//cout << "Serial: " << serial(x509) << endl;
	//cout << "Issuer: " << issuer_one_line(x509) << endl;
	//map<string, string> ifields = issuer(x509);
	//for (map<string, string>::iterator i = ifields.begin(), ix = ifields.end(); i != ix; i++)
	//	cout << " * " << i->first << " : " << i->second << endl;
	//cout << "Subject: " << typeid(subject_one_line(x509)).name() << endl;
	map<string, string> sfields = subject(x509);
	for (map<string, string>::iterator i = sfields.begin(), ix = sfields.end(); i != ix; i++) {
		if (i->first == "CN") {
			cns.push_back(i->second);
		}
	}
	//	cout << " * " << i->first << " : " << i->second << endl;
	//cout << "SignatureAlgorithm: " << signature_algorithm(x509) << endl;
	//cout << "PublicKeyType: " << public_key_type(x509) << public_key_ec_curve_name(x509) << endl;
	//cout << "PublicKeySize: " << public_key_size(x509) << endl;
	//cout << "NotBefore: " << asn1datetime_isodatetime(X509_get_notBefore(x509)) << endl;
	//cout << "NotAfter: " << asn1datetime_isodatetime(X509_get_notAfter(x509)) << endl;
	//cout << "SubjectAltName(s):" << endl;
	//vector<string> sans = subject_alt_names(x509);
	//for (int i = 0, ix = sans.size(); i < ix; i++) {
	//	cout << " " << sans[i] << endl;
	//}
	//cout << "CRL URLs:" << endl;
	//vector<string> crls = crl_urls(x509);
	//for (int i = 0, ix = crls.size(); i < ix; i++) {
	//	cout << " " << crls[i] << endl;
	//}
	//cout << "OCSP URLs:" << endl;
	//vector<string> urls = ocsp_urls(x509);
	//for (int i = 0, ix = urls.size(); i < ix; i++) {
	//	cout << " " << urls[i] << endl;
	//}
	return cns;
}
//----------------------------------------------------------------------

int main(int argc, char **argv)
{
	OpenSSL_add_all_algorithms();

	const char bytes[] = "-----BEGIN CERTIFICATE-----" "\n"
		"MIIG4TCCBcmgAwIBAgIQCd0Ux6hVwNaX+SICZIR/jzANBgkqhkiG9w0BAQUFADBm" "\n"
		"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" "\n"
		"d3cuZGlnaWNlcnQuY29tMSUwIwYDVQQDExxEaWdpQ2VydCBIaWdoIEFzc3VyYW5j" "\n"
		"ZSBDQS0zMB4XDTEzMDUxNDAwMDAwMFoXDTE2MDUxODEyMDAwMFowYDELMAkGA1UE" "\n"
		"BhMCQ0ExEDAOBgNVBAgTB0FsYmVydGExEDAOBgNVBAcTB0NhbGdhcnkxGTAXBgNV" "\n"
		"BAoTEFNBSVQgUG9seXRlY2huaWMxEjAQBgNVBAMMCSouc2FpdC5jYTCCASIwDQYJ" "\n"
		"KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJv2n5mZfX6NV0jZof1WdXGiY5Q/W0yD" "\n"
		"T6tUdIYUjgS8GDkeZJYjtwUCMYD2Wo3rF/1ZJ8p9p2WBP1F3CVvjgO+VeA7tLJsf" "\n"
		"uAr+S8GE1q5tGO9+lPFkBAZkU38FNfBUblvz1imWb6ORXMc++HjUlrUB0nr2Ae8T" "\n"
		"1I3K0XGArHJyW5utJ5Xm8dNEYCcs6EAXchiViVtcZ2xIlSQMs+AqhqnZXo2Tt1H+" "\n"
		"f/tQhQJeMTkZ2kklUcnQ1izdTigMgkOvNzW4Oyd9Z0sBbxzUpneeH3nUB5bEv3MG" "\n"
		"4JJx7cAVPE4rqjVbtm3v0QbCL/X0ZncJiKl7heKWO+j3DnDZS/oliIkCAwEAAaOC" "\n"
		"A48wggOLMB8GA1UdIwQYMBaAFFDqc4nbKfsQj57lASDU3nmZSIP3MB0GA1UdDgQW" "\n"
		"BBTk00KEbrhrTuVWBY2cPzTJd1c1BTBkBgNVHREEXTBbggkqLnNhaXQuY2GCB3Nh" "\n"
		"aXQuY2GCCmNwLnNhaXQuY2GCDmNwLXVhdC5zYWl0LmNhghd1YXQtaW50ZWdyYXRp" "\n"
		"b24uc2FpdC5jYYIQdWF0LWFwYXMuc2FpdC5jYTAOBgNVHQ8BAf8EBAMCBaAwHQYD" "\n"
		"VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMGEGA1UdHwRaMFgwKqAooCaGJGh0" "\n"
		"dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9jYTMtZzIxLmNybDAqoCigJoYkaHR0cDov" "\n"
		"L2NybDQuZGlnaWNlcnQuY29tL2NhMy1nMjEuY3JsMIIBxAYDVR0gBIIBuzCCAbcw" "\n"
		"ggGzBglghkgBhv1sAQEwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2lj" "\n"
		"ZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFW" "\n"
		"HoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBm" "\n"
		"AGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0" "\n"
		"AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAv" "\n"
		"AEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0" "\n"
		"AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAg" "\n"
		"AGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBw" "\n"
		"AG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBu" "\n"
		"AGMAZQAuMHsGCCsGAQUFBwEBBG8wbTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au" "\n"
		"ZGlnaWNlcnQuY29tMEUGCCsGAQUFBzAChjlodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy" "\n"
		"dC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlQ0EtMy5jcnQwDAYDVR0TAQH/BAIw" "\n"
		"ADANBgkqhkiG9w0BAQUFAAOCAQEAcl2YI0iMOwx2FOjfoA8ioCtGc5eag8Prawz4" "\n"
		"FFs9pMFZfD/K8QvPycMSkw7kPtVjmuQWxNtRAvCSIhr/urqNLBO5Omerx8aZYCOz" "\n"
		"nsmZpymxMt56DBw+KZrWIodsZx5QjVngbE/qIDLmsYgtKczhTCtgEM1h/IHlO3Ho" "\n"
		"7IXd2Rr4CqeMoM2v+MTV2FYVEYUHJp0EBU/AMuBjPf6YT/WXMNq6fn+WJpxcqwJJ" "\n"
		"KtBh7c2vRTklahbh1FaiJ0aFJkDH4tasbD69JQ8R2V5OSuGH6Q7EGlpNl+unqtUy" "\n"
		"KsAL86HvgzF5D51C9TmFXEtXTlPKnjoqn1TC4Rqpqvh+FHWPJQ==" "\n"
		"-----END CERTIFICATE-----";
	BIO *bio_mem = BIO_new(BIO_s_mem());
	BIO_puts(bio_mem, bytes);
	X509 * x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
	//parseCert1(x509);
	//parseCert2(x509);
	parseCert3(x509);
	BIO_free(bio_mem);
	X509_free(x509);
}
*/

#endif