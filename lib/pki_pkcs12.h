/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_PKCS12_H
#define __PKI_PKCS12_H

#include "pki_multi.h"

class pki_key;
class pki_x509;

class encAlgo
{
	private:
	static int default_encAlgo;
	int encAlgo_nid;

	public:
	static const QList<int> all_encAlgos;

	encAlgo(int nid);
	encAlgo(const QString &name);
	encAlgo(const encAlgo &d) = default;
	encAlgo& operator=(const encAlgo &d) = default;

	QString name() const;
	int getEncAlgoNid() const;

	static void setDefault(const QString &def);
	static const encAlgo getDefault();
};

class pki_pkcs12: public pki_multi
{
	Q_OBJECT
	friend class pki_x509;
	friend class pki_evp;

	protected:
		QString alias;
		pki_x509 *cert;
		pki_key *key;

	public:
		pki_pkcs12(const QString &d, pki_x509 *acert, pki_key *akey);
		pki_pkcs12(const QString &fname);

		pki_key *getKey() const
		{
			return key;
		}
		pki_x509 *getCert() const
		{
			return cert;
		}
		void writePKCS12(XFile &file, encAlgo &encAlgo) const;
};
#endif
