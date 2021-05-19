/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2021 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DIGEST_H
#define __DIGEST_H

#include <openssl/evp.h>
#include <QString>

class digest
{
    private:
	static int default_md;
	int md_nid;

    public:
	static const QList<int> all_digests;

	digest(int nid);
	digest(const EVP_MD *md);
	digest(const QString &name);
	digest(const digest &d);

	bool isInsecure() const;
	const EVP_MD *MD() const;
	QString name() const;

	static void setDefault(const QString &def);
	static const digest getDefault();
};

#endif
