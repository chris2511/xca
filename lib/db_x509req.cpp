#include "db_x509req.h"


pki_base *db_x509req::newPKI(){
	return new pki_x509req();
}

