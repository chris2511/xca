#include "pki_key.h"


pki_key::pki_key(const string d, void (*cb)(int, int,void *),void *prog, int bits = 1024, int type = EVP_PKEY_RSA): pki_base(d)
{
	onlyPubKey = false;
	key = EVP_PKEY_new();
	key->type = type;
	if (type == EVP_PKEY_RSA) {
	   RSA *rsakey;
	   rsakey = RSA_generate_key(bits, 0x10001, cb, prog);
	   openssl_error();	
	   if (rsakey) EVP_PKEY_assign_RSA(key, rsakey);
	}
}

pki_key::pki_key(const string d, int type = EVP_PKEY_RSA)
	:pki_base(d)
{ 
	onlyPubKey = false;
	key = EVP_PKEY_new();
	key->type = type;
}	

pki_key::pki_key(const string fname, pem_password_cb *cb, int type=EVP_PKEY_RSA)
	:pki_base(fname)
{ 
	key = EVP_PKEY_new();
	type = type;
	onlyPubKey = false;
	error = "";
	FILE *fp = fopen(fname.data(), "r");
	RSA *rsakey = NULL;
	key = NULL;
	if (fp != NULL) {
	   rsakey = PEM_read_RSAPrivateKey(fp, NULL, cb, NULL);
	   if (!rsakey) {
		openssl_error();
		rewind(fp);
		cerr << "Fallback to privatekey DER" << endl; 
	   	rsakey = d2i_RSAPrivateKey_fp(fp, NULL);
	   }
	   if (!rsakey) {
		onlyPubKey = true;
		openssl_error();
		rewind(fp);
		cerr << "Fallback to pubkey" << endl; 
	   	rsakey = PEM_read_RSA_PUBKEY(fp, NULL, cb, NULL);
	   }
	   if (!rsakey) {
		openssl_error();
		rewind(fp);
		cerr << "Fallback to pubkey DER" << endl; 
	   	rsakey = d2i_RSA_PUBKEY_fp(fp, NULL);
	   }
	   if (!rsakey) {
	        openssl_error();
	        rewind(fp);
	        cerr << "Fallback to PKCS#8 Private key" << endl; 
	        if (d2i_PKCS8PrivateKey_fp(fp, &key, cb, NULL))
			onlyPubKey = false;
	   }
	   else {
	   	EVP_PKEY_assign_RSA(key,rsakey);
	   }
	   int r = fname.rfind('.');
	   int l = fname.rfind('/');
	   setDescription(fname.substr(l,r));
	   openssl_error();
	}	
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}


void pki_key::fromData(unsigned char *p, int size )
{
	cerr << "KEY fromData\n";
	return;
	unsigned char *sik;
	sik = (unsigned char *)OPENSSL_malloc(size);
	RSA *rsakey;
	memcpy(sik,p,size);
	onlyPubKey = false;
	cerr << "Key newdata\n";
	if (key->type == EVP_PKEY_RSA) {
	   rsakey = d2i_RSAPrivateKey(NULL, &p, size);
	   if (openssl_error()) {
		onlyPubKey = true;
		rsakey = d2i_RSA_PUBKEY(NULL, &sik, size);
	   }
	   openssl_error(); 
	   if (rsakey) EVP_PKEY_assign_RSA(key, rsakey);
	}
	OPENSSL_free(sik);
}


unsigned char *pki_key::toData(int *size) 
{
	cerr << "KEY toData\n";
	unsigned char *p = NULL , *p1;
	if (key->type == EVP_PKEY_RSA) {
	   RSA * rsakey = EVP_PKEY_get1_RSA(key);
	   if (onlyPubKey) {
	      *size = i2d_RSA_PUBKEY(rsakey, NULL);
	      openssl_error();
	      p = (unsigned char *)OPENSSL_malloc(*size);
	      p1 = p;
	      i2d_RSA_PUBKEY(rsakey, &p1);
	   openssl_error();
	   }
	   else {
	      *size = i2d_RSAPrivateKey(rsakey, NULL);
	      openssl_error();
	      p = (unsigned char *)OPENSSL_malloc(*size);
	      p1 = p;
	      i2d_RSAPrivateKey(rsakey, &p1);
	      openssl_error();
	   }
	}
	return p;
}



pki_key::~pki_key()
{
	//RSA_free(key);
	EVP_PKEY_free(key);
}


void pki_key::writePKCS8(const string fname, pem_password_cb *cb)
{
	FILE *fp = fopen(fname.data(),"w");
	if (fp != NULL) {
	   if (key){
		cerr << "writing PKCS8\n";
		PEM_write_PKCS8PrivateKey_nid(fp, key, 
		   NID_pbeWithMD5AndDES_CBC, NULL, 0, cb, 0);
		openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}

void pki_key::writeKey(const string fname, EVP_CIPHER *enc, 
			pem_password_cb *cb, bool PEM)
{
	if (onlyPubKey) {
		writePublic(fname, PEM);
		return;
	}
	FILE *fp = fopen(fname.data(),"w");
	if (fp != NULL) {
	   if (key){
		cerr << "writing Private Key\n";
		if (PEM) 
		   PEM_write_PrivateKey(fp, key, enc, NULL, 0, cb, NULL);
		else {
		   RSA *rsakey = EVP_PKEY_get1_RSA(key);
		   i2d_RSAPrivateKey_fp(fp, rsakey);
	        }
	   openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}


void pki_key::writePublic(const string fname, bool PEM)
{
	FILE *fp = fopen(fname.data(),"w");
	if (fp != NULL) {
	   if (key->type == EVP_PKEY_RSA) {
		RSA *rsakey = EVP_PKEY_get1_RSA(key);
		cerr << "writing Public Key\n";
		if (PEM)
		   PEM_write_RSA_PUBKEY(fp, rsakey);
		else
		   i2d_RSA_PUBKEY_fp(fp, rsakey);
		openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}


string pki_key::length()
{
	RSA *rsakey = EVP_PKEY_get1_RSA(key);
	string x;
	x = (RSA_size(rsakey) * 8 );
	x +=  " bits";
	return x;
}

string pki_key::BN2string(BIGNUM *bn)
{
	char *buf = BN_bn2hex(bn);
	string x = buf; 
	OPENSSL_free(buf);
	return x;
}

string pki_key::modulus() {
	RSA *rsakey = EVP_PKEY_get1_RSA(key);
	return BN2string(rsakey->n);
}

string pki_key::pubEx() {
	RSA *rsakey = EVP_PKEY_get1_RSA(key);
	return BN2string(rsakey->e);
}

string pki_key::privEx() {
	if (onlyPubKey) return "Nicht vorhanden (kein privater Schlüssel)";
	RSA *rsakey = EVP_PKEY_get1_RSA(key);
	return BN2string(rsakey->d);
}

bool pki_key::compare(pki_base *ref)
{
	RSA *rsakey = EVP_PKEY_get1_RSA(key);
	RSA *rsarefkey = EVP_PKEY_get1_RSA(((pki_key *)ref)->key);
	if (
	   BN_cmp(rsakey->n, rsarefkey->n) ||
	   BN_cmp(rsakey->e, rsarefkey->e)
	) return false;
	return true;
}	


bool pki_key::isPubKey()
{
	return onlyPubKey;
	
}


bool pki_key::isPrivKey()
{
	return ! onlyPubKey;
	
}

