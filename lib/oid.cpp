/* here we have the possibility to add out own OIDS */

#include <openssl/objects.h>

char *our_oids[] = {
"1.3.6.1.4.1.311.20.2", "dom", "Domain Controller",
"1.3.6.1.4.1.311.21.1", "MsCaV", "Microsoft CA Version",
NULL };

void initOIDs() {
	int i=0;
	while (our_oids[i] != NULL) {
		 OBJ_create(our_oids[i], our_oids[i+1], our_oids[i+2]);
		 i+=3;
	}
}

