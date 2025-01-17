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
//#include "base64.h"


using std::cout;
using std::endl;
using std::stringstream;
using std::map;
using std::vector;
using std::string;

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
std::map<string, string> subject(X509* x509)
{
	return _subject_as_map(X509_get_subject_name(x509));
}



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


//string sha256(const string str)
vector<unsigned char> sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    //stringstream ss;
    //for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    //{
    //    ss << hex << setw(2) << setfill('0') << (int)hash[i];
    //}
    //return ss.str();
    std::vector<unsigned char> vec(hash, hash + SHA256_DIGEST_LENGTH);
    return vec;
}


bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic) {							 
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
  //Base64Decode(signatureBase64, &encMessage, &encMessageLength);
  std::vector<BYTE> decode = base64_decode(signatureBase64);
  encMessage = &decode[0];
  encMessageLength = decode.size();
  bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
  return result & authentic;
}



RSA* getPub(X509* x509) {
	X509* cert;
	EVP_PKEY* pubkey;
	RSA* rsa = RSA_new();
	pubkey = X509_get_pubkey(x509);
	rsa = EVP_PKEY_get1_RSA(pubkey);
	//EVP_PKEY_free(pubkey);
	return rsa;
}


#endif
