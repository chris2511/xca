#include "pki_key.h"

char pki_key::passwd[30]="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

pki_key::pki_key(const string d, void (*cb)(int, int,void *),void *prog, int bits = 1024, int type = EVP_PKEY_RSA): pki_base(d)
{
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
	key = EVP_PKEY_new();
	key->type = type;
}	

pki_key::pki_key(EVP_PKEY *pkey)
	:pki_base("")
{ 
	key = pkey;
}	

pki_key::pki_key(const string fname, pem_password_cb *cb, int type=EVP_PKEY_RSA)
	:pki_base(fname)
{ 
	key = EVP_PKEY_new();
	key->type = EVP_PKEY_type(type);
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
	        d2i_PKCS8PrivateKey_fp(fp, &key, cb, NULL);
	   }
	   else {
	   	EVP_PKEY_set1_RSA(key,rsakey);
		openssl_error();
		cerr << "assigning loaded key\n";
	   }
	   int r = fname.rfind('.');
	   int l = fname.rfind('/');
	   cerr << fname << "r,l: "<< r <<","<< l << endl;
	   setDescription(fname.substr(l+1,r-l-1));
	   openssl_error();
	   //if ( verify() != pki_base::VERIFY_OK)
		//   cerr << "RSA key is faulty !!\n";
	}	
	else error = "Fehler beim Öffnen der Datei";
	cerr << "endofloading\n";
	fclose(fp);
}


bool pki_key::fromData(unsigned char *p, int size )
{
	cerr << "KEY fromData\n";
	unsigned char *sik, *pdec, *pdec1, *sik1;
	int outl, decsize;
	RSA *rsakey;
	EVP_CIPHER_CTX ctx;
	sik = (unsigned char *)OPENSSL_malloc(size);
	if ( sik == NULL ) return false;
	pdec = (unsigned char *)OPENSSL_malloc(size);
	if (pdec == NULL ) {OPENSSL_free(sik); return false;}
	pdec1=pdec;
	sik1=sik;
	
	EVP_CIPHER_CTX_init (&ctx);
	EVP_DecryptInit( &ctx, EVP_des_ede3_cbc(),(unsigned char *)passwd, NULL);
	EVP_DecryptUpdate( &ctx, pdec, &outl, p, size );
	decsize = outl;
	EVP_DecryptFinal( &ctx, pdec + decsize, &outl );
	decsize += outl;
	cerr << "Encr done: " << size << "--" << decsize << endl;
	if (openssl_error()) return false;
	memcpy(sik, pdec, decsize);
	if (key->type == EVP_PKEY_RSA) {
	   rsakey = d2i_RSAPrivateKey(NULL, &pdec, decsize);
	   if (openssl_error()) {
		rsakey = d2i_RSA_PUBKEY(NULL, &sik, decsize);
	   }
	   if (openssl_error()) return false; 
	   if (rsakey) EVP_PKEY_set1_RSA(key, rsakey);
	}
	OPENSSL_free(sik1);
	OPENSSL_free(pdec1);
	return true;
}


unsigned char *pki_key::toData(int *size) 
{
	cerr << "KEY toData " << getDescription()<< endl;
	unsigned char *p, *p1, *penc;
	int outl, encsize=0;
	EVP_CIPHER_CTX ctx;
	
	EVP_CIPHER_CTX_init (&ctx);
	EVP_EncryptInit( &ctx, EVP_des_ede3_cbc(),(unsigned char *)passwd , NULL);
	if (key->type == EVP_PKEY_RSA) {
	   if (isPubKey()) {
	      *size = i2d_RSA_PUBKEY(key->pkey.rsa, NULL);
	      cerr << "Sizeofpubkey: " << *size <<endl;
	      openssl_error();
	      p = (unsigned char *)OPENSSL_malloc(*size);
	      penc = (unsigned char *)OPENSSL_malloc(*size +  EVP_MAX_KEY_LENGTH - 1);
	      p1 = p;
	      i2d_RSA_PUBKEY(key->pkey.rsa, &p1);
	      EVP_EncryptUpdate( &ctx, penc, &outl, p, *size );
	      encsize = outl;
	      openssl_error();
	      
	   }
	   else {
	      *size = i2d_RSAPrivateKey(key->pkey.rsa, NULL);
	      cerr << "Sizeofprivkey: " << *size <<endl;
	      openssl_error();
	      p = (unsigned char *)OPENSSL_malloc(*size);
	      penc = (unsigned char *)OPENSSL_malloc(*size +  EVP_MAX_KEY_LENGTH - 1);
	      p1 = p;
	      i2d_RSAPrivateKey(key->pkey.rsa, &p1);
	      EVP_EncryptUpdate( &ctx, penc, &outl, p, *size );
	      encsize = outl;
	      openssl_error();
	   }
	}
	EVP_EncryptFinal( &ctx, penc + encsize, &outl );
	encsize += outl;
	OPENSSL_free(p);
	
	cerr << "KEY toData end ..."<< encsize << "--"<<*size <<endl;
	*size = encsize;
	return penc;
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
	if (isPubKey()) {
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
	if (isPubKey()) return "Nicht vorhanden (kein privater Schlüssel)";
	return BN2string(key->pkey.rsa->d);
}

bool pki_key::compare(pki_base *ref)
{
	pki_key *kref = (pki_key *)ref;
	if (kref == NULL) return false;
	if (kref->key == NULL) return false;
	if (kref->key->pkey.rsa->n == NULL) return false;
	if (key == NULL) return false;
	if (key->pkey.rsa->n == NULL) return false;
	if (
	   BN_cmp(key->pkey.rsa->n, kref->key->pkey.rsa->n) ||
	   BN_cmp(key->pkey.rsa->e, kref->key->pkey.rsa->e) 
	) return false;
	return true;
}	


bool pki_key::isPubKey()
{
	if (key == NULL) {
	   cerr << "key is null" <<endl;
	   return false;
	}
	if (key->pkey.rsa == 0) {
	   cerr << "key->pkey is null" <<endl;
	   return false;
	}
	return (key->pkey.rsa->d == NULL);
	
}

bool pki_key::isPrivKey()
{
	return ! isPubKey();
	
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
		
int pki_key::getType()
{
	return key->type;
}
