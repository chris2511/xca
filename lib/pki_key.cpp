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
	   if (rsakey) EVP_PKEY_set1_RSA(key, rsakey);
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
	key->type = EVP_PKEY_type(type);
	onlyPubKey = false;
	error = "";
	FILE *fp = fopen(fname.c_str(), "r");
	RSA *rsakey = NULL;
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
	   	EVP_PKEY_set1_RSA(key,rsakey);
		openssl_error();
		cerr << "assigning loaded key\n";
		if (isPubKey()) {
			rsakey->d = NULL;
			rsakey->p = NULL;
			rsakey->q = NULL;
			rsakey->dmp1 = NULL;
			rsakey->dmq1 = NULL;
			rsakey->iqmp = NULL;
		}
	   }
	   int r = fname.rfind('.');
	   int l = fname.rfind('/');
	   cerr << fname << "r,l: "<< r <<","<< l << endl;
	   setDescription(fname.substr(l+1,r-l-1));
	   openssl_error();
	   if ( verify() != pki_base::VERIFY_OK)
		   cerr << "RSA key is faulty !!\n";
	}	
	else error = "Fehler beim Öffnen der Datei";
	cerr << "endofloading\n";
	fclose(fp);
}


void pki_key::fromData(unsigned char *p, int size )
{
	cerr << "KEY fromData\n";
	unsigned char *sik;
	sik = (unsigned char *)OPENSSL_malloc(size);
	RSA *rsakey;
	memcpy(sik,p,size);
	onlyPubKey = false;
	if (key->type == EVP_PKEY_RSA) {
	   rsakey = d2i_RSAPrivateKey(NULL, &p, size);
	   if (openssl_error()) {
		onlyPubKey = true;
		rsakey = d2i_RSA_PUBKEY(NULL, &sik, size);
	   }
	   openssl_error(); 
	   if (rsakey) EVP_PKEY_set1_RSA(key, rsakey);
	}
	OPENSSL_free(sik);
}


unsigned char *pki_key::toData(int *size) 
{
	cerr << "KEY toData " << getDescription()<< endl;
	unsigned char *p = NULL , *p1;
	if (key->type == EVP_PKEY_RSA) {
	   if (isPubKey()) {
	      *size = i2d_RSA_PUBKEY(key->pkey.rsa, NULL);
	      cerr << "Sizeofpubkey: " << *size <<endl;
	      openssl_error();
	      p = (unsigned char *)OPENSSL_malloc(*size);
	      p1 = p;
	      i2d_RSA_PUBKEY(key->pkey.rsa, &p1);
	   openssl_error();
	   }
	   else {
	      *size = i2d_RSAPrivateKey(key->pkey.rsa, NULL);
	      cerr << "Sizeofprivkey: " << *size <<endl;
	      openssl_error();
	      p = (unsigned char *)OPENSSL_malloc(*size);
	      p1 = p;
	      i2d_RSAPrivateKey(key->pkey.rsa, &p1);
	      openssl_error();
	   }
	}
	cerr << "KEY toData end ...\n";
	return p;
}



pki_key::~pki_key()
{
	//RSA_free(key);
	EVP_PKEY_free(key);
}


void pki_key::writePKCS8(const string fname, pem_password_cb *cb)
{
	FILE *fp = fopen(fname.c_str(),"w");
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
	FILE *fp = fopen(fname.c_str(),"w");
	if (fp != NULL) {
	   if (key){
		cerr << "writing Private Key\n";
		if (PEM) 
		   PEM_write_PrivateKey(fp, key, enc, NULL, 0, cb, NULL);
		else {
		   i2d_RSAPrivateKey_fp(fp, key->pkey.rsa);
	        }
	   openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}


void pki_key::writePublic(const string fname, bool PEM)
{
	FILE *fp = fopen(fname.c_str(),"w");
	if (fp != NULL) {
	   if (key->type == EVP_PKEY_RSA) {
		cerr << "writing Public Key\n";
		if (PEM)
		   PEM_write_RSA_PUBKEY(fp, key->pkey.rsa);
		else
		   i2d_RSA_PUBKEY_fp(fp, key->pkey.rsa);
		openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}


string pki_key::length()
{
	char st[64];
	sprintf(st,"%i bit", EVP_PKEY_size(key) * 8 );
	string x = st;
	return x;
}

string pki_key::BN2string(BIGNUM *bn)
{
	if (bn == NULL) return "--";
	char *buf = BN_bn2hex(bn);
	string x = buf; 
	OPENSSL_free(buf);
	return x;
}

string pki_key::modulus() {
	return BN2string(key->pkey.rsa->n);
}

string pki_key::pubEx() {
	return BN2string(key->pkey.rsa->e);
}

string pki_key::privEx() {
	if (onlyPubKey) return "Nicht vorhanden (kein privater Schlüssel)";
	return BN2string(key->pkey.rsa->d);
}

bool pki_key::compare(pki_base *ref)
{
	pki_key *kref = (pki_key *)ref;
	if (kref == NULL) return false;
	if (kref->key == NULL) return false;
	if (kref->key->pkey.rsa->n == NULL) return false;
	cerr<< "Ref is ok\n";
	if (key == NULL) return false;
	if (key->pkey.rsa->n == NULL) return false;
	cerr << "PKI key compare\n";
	if (
	   BN_cmp(key->pkey.rsa->n, kref->key->pkey.rsa->n) ||
	   BN_cmp(key->pkey.rsa->e, kref->key->pkey.rsa->e) 
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

int pki_key::verify()
{
	bool veri = false;
	return true;
	cerr<< "verify start\n";
	if (key->type == EVP_PKEY_RSA && isPrivKey()) {
	   if (RSA_check_key(key->pkey.rsa) == 1) veri = true;
	}
	if (isPrivKey()) veri = true;
	openssl_error();
	cerr<< "verify end: "<< veri << endl;;
	if (veri) return pki_base::VERIFY_OK;
	else  return pki_base::VERIFY_ERROR;
}
		
