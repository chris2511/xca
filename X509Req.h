#include <stdio.h>
#include <qobject.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "RSAkey.h"

#ifndef X509REQ_H
#define X509REQ_H

class X509Req : public QObject
{
	Q_OBJECT
	   X509_REQ *request;
	   char *error;
	   QString desc;
	public:
	   X509Req(RSAkey *key, const char *cn, 
		   const char *c, const char *l,
		   const char *st,const char *o,
		   const char *ou,const char *email,
		   QObject *parent, const char *name = 0);
	   X509Req(unsigned char *p, int size);
	   char *openssl_error();
	   void setDescription(QString d);
	   QString description();
	   unsigned char *getReq(int *size);
};

#endif
