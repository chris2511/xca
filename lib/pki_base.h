#include <iostream>
#include <string>
#include <openssl/err.h>

#ifndef PKI_BASE_H
#define PKI_BASE_H


typedef struct PASS_INFO {
	string *title;
	string *description;
};


class pki_base
{
    protected:
	string desc;
	string error;
	bool openssl_error();
	void *pointer; 
    public:
	enum { VERIFY_ERROR, VERIFY_SELFSIGNED, VERIFY_TRUSTED, 
	       VERIFY_UNTRUSTED, VERIFY_OK }; 
	pki_base(const string d);
	pki_base();
	virtual bool fromData(unsigned char *p, int size){
		cerr << "VIRTUAL FUNCTION CALLED: fromData\n"; return false; };
	virtual unsigned char *toData(int *size){
		cerr << "VIRTUAL FUNCTION CALLED: toData\n";
		return NULL;};
	virtual bool compare(pki_base *ref){
		cerr << "VIRTUAL FUNCTION CALLED: compare\n";
		return false;};
	virtual ~pki_base();
        string getDescription();
        void setDescription(const string d );
	string getError();
	void setPointer(void *ptr) { pointer = ptr; }
	void delPointer() { pointer = NULL; }
	void *getPointer() { return pointer; }
};

#endif
