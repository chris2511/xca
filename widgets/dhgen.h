/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DHGEN_H
#define __DHGEN_H

#include "lib/entropy.h"
#include "lib/exception.h"
#include "lib/xfile.h"

#include <openssl/rand.h>
#include <openssl/dh.h>

#include <QString>
#include <QThread>

class DHgen: public QThread
{
	QString fname;
	int bits;

    public:
	errorEx error;
	DHgen(const QString &n, int b) : QThread()
	{
		fname = n;
		bits = b;
	}
	const QString &filename() const
	{
		return fname;
	}
    protected:
	void run()
	{
		DH *dh = NULL;
		try {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			dh = DH_new();
			check_oom(dh);
			DH_generate_parameters_ex(dh, bits, 2, NULL);
#else
			dh = DH_generate_parameters(bits, 2, NULL, NULL);
			check_oom(dh);
#endif
			openssl_error();

			XFile file(fname);
			file.open_write();
			PEM_write_DHparams(file.fp(), dh);
			openssl_error();
		} catch (errorEx &err) {
			error = err;
		}
		if (dh)
			DH_free(dh);
	}
};
#endif
