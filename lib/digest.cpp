/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2021 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "digest.h"
#include "lib/base.h"
#include <QList>
#include <QDebug>

const QList<int> digest::all_digests(
	{ NID_md5, NID_ripemd160, NID_sha1,
	  NID_sha224, NID_sha256, NID_sha384, NID_sha512
});

int digest::default_md(NID_sha256);

digest::digest(int nid) : md_nid(nid)
{
}

digest::digest(const EVP_MD *md) : md_nid(default_md)
{
	if (!OBJ_find_sigid_algs(EVP_MD_type(md), &md_nid, NULL))
		md_nid = EVP_MD_type(md);
}

digest::digest(const QString &name) : md_nid(default_md)
{
	QString s(name);
	md_nid = OBJ_txt2nid(CCHAR(s.remove(QChar(' '))));
}

digest::digest(const digest &d) : md_nid(d.md_nid)
{
}

bool digest::isInsecure() const
{
	switch (md_nid) {
	case NID_md5:
	case NID_ripemd160:
	case NID_sha1:
		return true;
	}
	return false;
}

const EVP_MD *digest::MD() const
{
	return EVP_get_digestbynid(md_nid);
}

QString digest::name() const
{
	return OBJ_nid2sn(md_nid);
}

const digest digest::getDefault()
{
	return digest(default_md);
}

void digest::setDefault(const QString &def)
{
	default_md = digest(def).md_nid;
}
