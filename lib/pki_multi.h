/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __PKI_MULTI_H
#define __PKI_MULTI_H

#include <openssl/pem.h>
#include "pki_x509.h"
#include "x509name.h"
#include "asn1time.h"
#include "asn1int.h"

class pki_multi: public pki_base
{
		Q_OBJECT
	protected:
		QList<pki_base*> multi;
	public:
		pki_multi(const QString name = "");
		~pki_multi();
		void fromPEM_BIO(BIO *bio, QString name);
		void fload(const QString fname);
		void probeAnything(const QString fname);
		pki_base *pull();
		int count() const
		{
			return multi.count();
		}

};

#endif
