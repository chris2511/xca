/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "func.h"
#include "dhgen.h"
#include "entropy.h"
#include "xfile.h"

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/dh.h>

void DHgen::run()
{
	DH *dh = NULL;
	try {
		dh = DH_new();
		check_oom(dh);
		DH_generate_parameters_ex(dh, bits, 2, NULL);
		openssl_error();

		XFile file(fname);
		file.open_write();
		PEM_write_DHparams(file.fp(), dh);
		openssl_error();
	} catch (errorEx &e) {
		err = e;
	}
	if (dh)
		DH_free(dh);
}
