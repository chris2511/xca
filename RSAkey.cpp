
#include "RSAkey.h"
#include <stdio.h>
#include <iostream.h>
#include <string.h>


RSAkey::RSAkey(const QString d, int bits, 
	void (*cb)(int, int,void *),void *prog,
	QObject *parent=0, const char *name=0)
	:QObject( parent, name)
{
	onlyPubKey = false;
	printf("Bits: %i\n",bits);
	desc = d;
	error = NULL;
	if ((key = RSA_generate_key(bits, 0x10001, cb, prog)) == NULL)
		openssl_error();	
}


RSAkey::RSAkey(const QString fname, pem_password_cb *cb, QObject *parent=0, const char *name=0)
	:QObject( parent, name)
{
	onlyPubKey = false;
	error = NULL;
	FILE *fp = fopen(fname.latin1(),"r");
	key = NULL;
	if (fp != NULL) {
	   key = PEM_read_RSAPrivateKey(fp, NULL, cb, NULL);
	   if (!key) {
		openssl_error();
		rewind(fp);
		printf("Fallback to privatekey DER\n"); 
	   	key = d2i_RSAPrivateKey_fp(fp, NULL);
	   }
	   if (!key) {
		onlyPubKey = true;
		openssl_error();
		rewind(fp);
		printf("Fallback to pubkey\n"); 
	   	key = PEM_read_RSA_PUBKEY(fp, NULL, cb, NULL);
	   }
	   if (!key) {
		openssl_error();
		rewind(fp);
		printf("Fallback to pubkey DER\n"); 
	   	key = d2i_RSA_PUBKEY_fp(fp, NULL);
	   }
	   if (!key) {
	        openssl_error();
	        rewind(fp);
	        printf("Fallback to PKCS#8 Private key\n"); 
	        EVP_PKEY *evpkey = d2i_PKCS8PrivateKey_fp(fp, NULL, cb, NULL);
	        key = EVP_PKEY_get1_RSA(evpkey);
	   }
	   int r = fname.findRev('.',-4);
	   int l = fname.findRev('/');
	   desc = fname.mid(l+1,r-l-1);
	   if (desc.isEmpty()) desc=fname;
	   openssl_error();
	}	
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
	
}

RSAkey::RSAkey(unsigned char *p, int size) 
{
	unsigned char *sik;
	sik = (unsigned char *)OPENSSL_malloc(size);
	memcpy(sik,p,size);
	onlyPubKey = false;
	key = d2i_RSAPrivateKey(NULL, &p, size);
	if (openssl_error()) {
		onlyPubKey = true;
		key = d2i_RSA_PUBKEY(NULL, &sik, size);
	}
	if (openssl_error()); 
	OPENSSL_free(sik);
}

unsigned char *RSAkey::getKey(int *size) 
{
	unsigned char *p, *p1;
	if (onlyPubKey) {
	   *size = i2d_RSA_PUBKEY(key, NULL);
	   openssl_error();
	   p = (unsigned char *)OPENSSL_malloc(*size);
	   p1 = p;
	   i2d_RSA_PUBKEY(key, &p1);
	   openssl_error();
	}
	else {
	   *size = i2d_RSAPrivateKey(key, NULL);
	   openssl_error();
	   p = (unsigned char *)OPENSSL_malloc(*size);
	   p1 = p;
	   i2d_RSAPrivateKey(key, &p1);
	   openssl_error();
	}
	return p;
}


RSAkey::RSAkey(RSA *rsa, QString &d,  QObject *parent=0, const char *name=0)
	:QObject( parent, name)
{
	error = NULL;
	key = rsa;
	desc = d;
}


RSAkey::~RSAkey()
{
	RSA_free(key);
}


void RSAkey::writePKCS8(const char *fname, pem_password_cb *cb)
{
	FILE *fp = fopen(fname,"w");
	if (fp != NULL) {
	   if (key){
		cerr << "writing PKCS8\n";
		EVP_PKEY pkey;
		EVP_PKEY_assign_RSA(&pkey,key);
		PEM_write_PKCS8PrivateKey_nid(fp, &pkey, 
		   NID_pbeWithMD5AndDES_CBC, NULL, 0, cb, 0);
		openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}


void RSAkey::writeKey(const char *fname, EVP_CIPHER *enc, 
			pem_password_cb *cb, bool PEM)
{
	if (onlyPubKey) {
		writePublic(fname, PEM);
		return;
	}
	FILE *fp = fopen(fname,"w");
	if (fp != NULL) {
	   if (key){
		cerr << "writing Private Key\n";
		if (PEM) 
		   PEM_write_RSAPrivateKey(fp, key, enc, NULL, 0, cb, NULL);
		else
		   i2d_RSAPrivateKey_fp(fp,key);
	       openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}

void RSAkey::writePublic(const char *fname, bool PEM)
{
	FILE *fp = fopen(fname,"w");
	if (fp != NULL) {
	   if (key) {
		cerr << "writing Public Key\n";
		if (PEM)
		   PEM_write_RSA_PUBKEY(fp, key);
		else
		   i2d_RSA_PUBKEY_fp(fp, key);
		openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}


QString RSAkey::description()
{
	QString x = desc;
	return x;
}


QString RSAkey::length()
{
	QString x;
	x.setNum( RSA_size(key) * 8 );
	x +=  " bits";
	return x;
}

QString RSAkey::BN2QString(BIGNUM *bn)
{
	char *buf = BN_bn2hex(bn);
	QString x = buf; 
	OPENSSL_free(buf);
	return x;
}

QString RSAkey::modulus() {
	return BN2QString(key->n);
}

QString RSAkey::pubEx() {
	return BN2QString(key->e);
}

QString RSAkey::privEx() {
	if (onlyPubKey) return "Not available";
	return BN2QString(key->d);
}

char *RSAkey::getError()
{
	char *x = error;
	error = NULL;
	return x;
}

void RSAkey::setDescription(QString x)
{
	desc = x;
}


char *RSAkey::openssl_error()
{
	error = NULL;
	char *errtxt = NULL;
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   if (errtxt) {
		fprintf(stderr, "OpenSSL: %s\n", errtxt);
	   }
	   error = errtxt;
	}
	return error;
}
