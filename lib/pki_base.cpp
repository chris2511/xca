#include "pki_base.h"


pki_base::pki_base(const string d)
{
	error = "";
	desc = d;
}

pki_base::pki_base()
{
	error = "";
	desc = "";
}

pki_base::~pki_base(void)
{}


string pki_base::getDescription()
{
	string x = desc;
	return x;
}


string pki_base::getError()
{
	string x = error;
	error = "";
	return x;
}


void pki_base::setDescription(const string d)
{
	desc = d;
}


bool pki_base::pki_error(string myerr)
{
	string errtxt = "";
	if (myerr != "") {
		CERR << "PKI: " << myerr << endl;
		error += myerr + "\n";
	}
	return openssl_error();
}


bool pki_base::openssl_error()
{
	string errtxt = "";
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   CERR << "OpenSSL: " << errtxt << endl;
	   error += errtxt + "\n";
	}
	return  (!error.empty());
}


bool pki_base::ign_openssl_error()
{
	// ignore openssl errors
	bool ret = false;
	string errtxt;
	while (int i = ERR_get_error() ) {
	   ret = true;
	   errtxt = ERR_error_string(i ,NULL);
	   CERR << "IGNORE: OpenSSL: " << errtxt << endl;
	}
	return ret;
}
