#include "pki_pkcs12.h"


pki_pkcs12::pki_pkcs12(const string d, pki_x509 *acert, pki_key *akey, pem_password_cb *cb):
	pki_base(d)
{
	key = akey;
	cert = acert;
	certstack = sk_X509_new_null();
	pkcs12 = NULL;
	passcb = cb;
	openssl_error();	
}

pki_pkcs12::pki_pkcs12(const string fname, pem_password_cb *cb)
	:pki_base(fname)
{ 
	FILE *fp;
	char pass[30];
	EVP_PKEY *mykey;
	X509 *mycert;
	PASS_INFO p;
	string title = "Password to import the PKCS#12 certificate";
	string description = "Please enter the password to encrypt the PKCS#12 bag.";
	p.title = &title;
	p.description = &description;
	fp = fopen(fname.c_str(), "rb");
	if (fp) {
		pkcs12 = d2i_PKCS12_fp(fp, NULL);
		if (openssl_error()) return;
		passcb(pass, 30, 0, &p);
		PKCS12_parse(pkcs12, pass, &mykey, &mycert, &certstack);
		if (openssl_error()) return;
		key = new pki_key(mykey);
		EVP_PKEY_free(mykey);
		cert = new pki_x509(mycert);
		X509_free(mycert);
	}
	else pki_error("Error opening file");
}	


pki_pkcs12::~pki_pkcs12()
{
	sk_X509_pop_free(certstack, X509_free); // free the certs itself, because we own a copy of them
	PKCS12_free(pkcs12);
}


void pki_pkcs12::addCaCert(pki_x509 *ca)
{ 
	if (ca == 0) return;
	sk_X509_push(certstack, X509_dup(ca->getCert()));
}	

void pki_pkcs12::writePKCS12(const string fname)
{ 
	char pass[30];
	char desc[100];
	strncpy(desc,getDescription().c_str(),100);
	PASS_INFO p;
	string title = "Password for the PKCS#12 bag";
	string description = "Please enter the password to encrypt the PKCS#12 bag.";
	p.title = &title;
	p.description = &description;
	if (!pkcs12) {
		if (cert == NULL || key == NULL) {
			pki_error("No key or no Cert and no pkcs12....");
			return;
		}
		passcb(pass, 30, 0, &p); 
		CERR << desc << key->getKey() << cert->getCert() <<endl;
		CERR << "before PKCS12_create...." <<endl;
		pkcs12 = PKCS12_create(pass, desc, key->getKey(), cert->getCert(), certstack, 0, 0, 0, 0, 0);
		if (openssl_error()) return;
		CERR << "after PKCS12_create...." <<endl;
	}
	FILE *fp = fopen(fname.c_str(),"wb");
	if (fp != NULL) {
	    CERR << "writing PKCS#12" << endl;
            i2d_PKCS12_fp(fp, pkcs12);
            openssl_error();
	    fclose (fp);
        }
	else pki_error("Error opening file");
}

int pki_pkcs12::num_ca() {
	return sk_X509_num(certstack);
}


pki_key *pki_pkcs12::getKey() {
	return key;
}


pki_x509 *pki_pkcs12::getCert() {
	return cert;
}

pki_x509 *pki_pkcs12::getCa(int x) {
	return new pki_x509(sk_X509_value(certstack, x));
}

