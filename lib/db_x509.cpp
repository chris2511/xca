#include "db_x509.h"


pki_base *db_x509::newPKI(){
	return new pki_x509();
}

