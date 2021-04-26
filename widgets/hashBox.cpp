/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2007 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "hashBox.h"
#include "lib/base.h"
#include <QDebug>

/* SHA-256 as default */
#define DEFAULT_MD_IDX 4

/* SHA 1 and below are insecure */
#define INSECURE_MD 2

static const struct {
	const char *name;
	int nid;
} hashalgos[] = {
	{ "MD 5", NID_md5 },
	{ "RIPEMD 160", NID_ripemd160 },
	{ "SHA 1", NID_sha1 },
	{ "SHA 224", NID_sha224 },
	{ "SHA 256", NID_sha256 },
	{ "SHA 384", NID_sha384 },
	{ "SHA 512", NID_sha512 },
};

int hashBox::default_md = DEFAULT_MD_IDX;

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

int hashBox::currentHashIdx() const
{
	QString hash = currentText();
	for (unsigned i=0; i<ARRAY_SIZE(hashalgos); i++) {
		if (hash == hashalgos[i].name)
			return i;
	}
	return DEFAULT_MD_IDX;
}

bool hashBox::isInsecure() const
{
	return currentHashIdx() <= INSECURE_MD;
}

const EVP_MD *hashBox::currentHash() const
{
	unsigned i = hashBox::currentHashIdx();

	if (i >= ARRAY_SIZE(hashalgos))
		i = DEFAULT_MD_IDX;
	return EVP_get_digestbynid(hashalgos[i].nid);
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

void hashBox::setCurrentMD(const EVP_MD *md)
{
	int hash_nid;
	unsigned idx;

	if (!md)
		return;

	if (!OBJ_find_sigid_algs(EVP_MD_type(md), &hash_nid, NULL))
		hash_nid = EVP_MD_type(md);
	for (idx = 0; idx<ARRAY_SIZE(hashalgos); idx++) {
		if (hash_nid == hashalgos[idx].nid) {
			setCurrentIndex(idx);
			return;
		}
	}
}

void hashBox::setupHashes(QList<int> nids)
{
	QString md = currentText();

	if (!wanted_md.isEmpty())
		md = wanted_md;
	clear();
	for (unsigned i=0; i<ARRAY_SIZE(hashalgos); i++) {
		if (nids.contains(hashalgos[i].nid)) {
			addItem(QString(hashalgos[i].name));
		}
	}
	setEnabled(count() > 0);
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

QString hashBox::currentHashName() const
{
	return currentText();
}

void hashBox::setDefaultHash()
{
	setCurrentString(hashalgos[default_md].name);
}

void hashBox::setDefault(QString def)
{
	for (unsigned i=0; i<ARRAY_SIZE(hashalgos); i++) {
		if (hashalgos[i].name == def) {
			default_md = i;
			return;
		}
	}
}

QString hashBox::getDefault()
{
	return QString(hashalgos[default_md].name);
}

const EVP_MD *hashBox::getDefaultMD()
{
	return EVP_get_digestbynid(hashalgos[default_md].nid);
}
