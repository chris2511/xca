#include <iostream>
#include <string>
#include <openssl/err.h>

#ifndef PKI_BASE_H
#define PKI_BASE_H

class pki_base
{
    protected:
	string desc;
	string error;
	bool openssl_error();
    public:
	virtual void fromData(unsigned char *p, int size);
	virtual unsigned char *toData(int *size);
	virtual bool compare(pki_base *ref);
	pki_base(const string d);
	pki_base();
	~pki_base();
        string getDescription();
        void setDescription(const string d );
	string getError();
};

#endif
