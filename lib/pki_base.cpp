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


bool pki_base::openssl_error()
{
	error = "";
	string errtxt = "";
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   cerr << "OpenSSL: " << errtxt << endl;
	   error += errtxt + "\n";
	}
	return  (!error.empty());
}
