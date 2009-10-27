/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "hashBox.h"
#include "lib/base.h"

#define DSA_INDEX 1

int hashBox::default_md = 1; /* SHA1 */

static struct {
	const char *name;
	const EVP_MD *md;
} hashalgos[] = {
	{ "MD 5", EVP_md5() },
	{ "SHA 1", EVP_sha1() },
#ifdef HAS_SHA256
	{ "SHA 256", EVP_sha256() },
	{ "SHA 512", EVP_sha512() },
#endif
	{ NULL, NULL },
};

hashBox::hashBox(QWidget *parent)
	:QComboBox(parent)
{
	for (int i=0; hashalgos[i].name; i++)
		if (hashalgos[i].md)
			addItem(QString(hashalgos[i].name));
	setDefaultHash();
	backup = default_md;
}

void hashBox::setKeyType(int type)
{
	if (key_type == type)
		return;
	if (type == EVP_PKEY_DSA || type == EVP_PKEY_EC) {
		if (key_type == EVP_PKEY_RSA)
			backup = currentIndex();
		setCurrentIndex(DSA_INDEX);
		setDisabled(true);
	} else {
		setCurrentIndex(backup);
		setDisabled(false);
	}
	key_type = type;
}

const EVP_MD *hashBox::currentHash()
{
	switch(key_type) {
	case EVP_PKEY_DSA:
		return EVP_dss1();
	case EVP_PKEY_EC:
		return EVP_ecdsa();
	default:
		return hashalgos[currentIndex()].md;
	}
}

QString hashBox::currentHashName()
{
	return QString(hashalgos[currentIndex()].name);
}

void hashBox::setDefaultHash()
{
	setCurrentIndex(default_md);
}

void hashBox::setCurrentAsDefault()
{
	default_md = currentIndex();
}

void hashBox::setDefault(QString def)
{
	for (int i=0; hashalgos[i].name; i++) {
		if (QString(hashalgos[i].name) == def) {
			default_md = i;
			return;
		}
	}
}

