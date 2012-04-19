/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2007 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "hashBox.h"
#include "lib/base.h"


static struct {
	const char *name;
	const EVP_MD *md;
} hashalgos[] = {
	{ "MD 5", EVP_md5() },
	{ "SHA 1", EVP_sha1() },
	{ "SHA 256", EVP_sha256() },
	{ "SHA 384", EVP_sha384() },
	{ "SHA 512", EVP_sha512() },
	{ "RIPEMD 160", EVP_ripemd160() },
};

QString hashBox::default_md = QString();

void hashBox::resetDefault()
{
	/* SHA1 */
	default_md = QString(hashalgos[1].name);
}

hashBox::hashBox(QWidget *parent)
	:QComboBox(parent)
{
	setupAllHashes();
	setDefaultHash();
}

void hashBox::setKeyType(int type)
{
	key_type = type;
}

const EVP_MD *hashBox::currentHash()
{
	switch(key_type) {
	case EVP_PKEY_DSA:
		return EVP_dss1();
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		return EVP_ecdsa();
#endif
	default:
		QString hash = currentText();
		for (unsigned i=0; i<ARRAY_SIZE(hashalgos); i++) {
			if (hash == hashalgos[i].name)
				return hashalgos[i].md;
		}
	}
	return hashalgos[1].md; /* SHA1 as fallback */
}

void hashBox::setCurrentString(QString md)
{
	int idx = findText(md);
	if (idx != -1) {
		setCurrentIndex(idx);
		wanted_md = "";
	} else {
		wanted_md = md;
	}
}

void hashBox::setupHashes(QList<int> nids)
{
	QString md = currentText();
	if (!wanted_md.isEmpty())
		md = wanted_md;
	clear();
	for (unsigned i=0; i<ARRAY_SIZE(hashalgos); i++) {
		if (nids.contains(hashalgos[i].md->type)) {
			addItem(QString(hashalgos[i].name));
		}
	}
	setDefaultHash();
	setCurrentString(md);
}

void hashBox::setupAllHashes()
{
	QString md = currentText();
	if (!wanted_md.isEmpty())
		md = wanted_md;
	clear();
	for (unsigned i=0; i<ARRAY_SIZE(hashalgos); i++) {
		addItem(QString(hashalgos[i].name));
	}
	setCurrentString(md);
}

QString hashBox::currentHashName()
{
	return currentText();
}

void hashBox::setDefaultHash()
{
	setCurrentString(default_md);
}

void hashBox::setCurrentAsDefault()
{
	default_md = currentText();
}

void hashBox::setDefault(QString def)
{
	default_md = def;
}

