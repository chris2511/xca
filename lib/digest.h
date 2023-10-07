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
	int md_nid{ NID_sha256 };

  public:
	static const QList<int> all_digests;

	digest() { };
	digest(int nid);
	digest(const EVP_MD *md);
	digest(const QString &name);
	digest(const digest &d) = default;
	digest& operator=(const digest &d) = default;
	void adjust(QList<int> nids);

	bool isInsecure() const;
	const EVP_MD *MD() const;
	QString name() const;

	static void setDefault(const QString &def);
	static const digest getDefault();
};

#endif
