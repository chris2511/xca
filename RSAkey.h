#include <stdio.h>
#include "qobject.h"
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#ifndef RSAKEY_H
#define RSAKEY_H

#define MAX_KEY_LENGTH 4096



class RSAkey: public QObject
{
	Q_OBJECT
	
	RSA *key;
	EVP_PKEY *evp;
	QString desc;
	char *error;
	QString BN2QString(BIGNUM *bn);	
	char *openssl_error();
	void initevp();
    public:
	bool onlyPubKey;
	EVP_PKEY *evpkey();
	RSAkey(const QString d, int bits,
		void (*cb)(int, int,void *),void *prog,
		QObject *parent=0, const char *name=0);   
	RSAkey(const QString fname,pem_password_cb *cb,
		QObject *parent=0, const char *name=0);   
	RSAkey(RSA *rsa, QString &d, 
		QObject *parent=0, const char *name=0);
	RSAkey(unsigned char *p, int size);
	~RSAkey();
        QString description();
        void setDescription(QString x);
        QString length();
        QString modulus();
        QString pubEx();
        QString privEx();
	char *getError();
	void writeKey(const char *fname,EVP_CIPHER *enc, 
			pem_password_cb *cb, bool PEM);
	void writePublic(const char *fname, bool PEM);
	void writePKCS8(const char *fname, pem_password_cb *cb);
	unsigned char *getKey(int *size);
};

#endif
