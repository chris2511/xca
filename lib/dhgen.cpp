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
#include "BioByteArray.h"

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/dh.h>

void DHgen::run()
{
	DH *dh = NULL;
	BioByteArray b;

	try {
		dh = DH_new();
		Q_CHECK_PTR(dh);
		DH_generate_parameters_ex(dh, bits, 2, NULL);
		openssl_error();
		PEM_write_bio_DHparams(b, dh);
		openssl_error();
	} catch (errorEx &e) {
		err = e;
	}
	XFile file(fname);
	file.open_write();
	file.write(b);

	if (dh)
		DH_free(dh);
}
