/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "hashBox.h"
#include "lib/base.h"

#define DSA_INDEX 2

#ifdef HAS_SHA256
int hashBox::default_md = 3; /* SHA256 */
#else
int hashBox::default_md = 2; /* SHA1 */
#endif

static struct {
	const char *name;
	const EVP_MD *md;
} hashalgos[] = {
	{ "MD 2", EVP_md2() },
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
		addItem(QString(hashalgos[i].name));
	setDefaultHash();
	backup = default_md;
}

void hashBox::setDsa(bool new_dsa)
{
	if (dsa == new_dsa)
		return;
	dsa = new_dsa;
	if (dsa) {
		backup = currentIndex();
		setCurrentIndex(DSA_INDEX);
		setDisabled(true);
	} else {
		setCurrentIndex(backup);
		setDisabled(false);
        }
}

const EVP_MD *hashBox::currentHash()
{
	if (dsa)
		return EVP_dss1();
	return hashalgos[currentIndex()].md;
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

