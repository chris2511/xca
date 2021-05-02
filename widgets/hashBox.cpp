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
	switch(key_type) {
#if OPENSSL_VERSION_NUMBER < 0x10000000L
	case EVP_PKEY_DSA:
		return EVP_dss1();
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		return EVP_ecdsa();
#endif
#endif
#ifdef EVP_PKEY_ED25519
        case EVP_PKEY_ED25519:
                return NULL;
#endif
	}
	unsigned i= hashBox::currentHashIdx();
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

#if OPENSSL_VERSION_NUMBER < 0x10000000L
struct nid_triple {
	int alg; int hash; int sig;
};

static const nid_triple sigoid_srt[] = {
    {NID_md2WithRSAEncryption, NID_md2, NID_rsaEncryption},
    {NID_md5WithRSAEncryption, NID_md5, NID_rsaEncryption},
    {NID_shaWithRSAEncryption, NID_sha, NID_rsaEncryption},
    {NID_sha1WithRSAEncryption, NID_sha1, NID_rsaEncryption},
    {NID_dsaWithSHA, NID_sha, NID_dsa},
    {NID_dsaWithSHA1_2, NID_sha1, NID_dsa_2},
    {NID_mdc2WithRSA, NID_mdc2, NID_rsaEncryption},
    {NID_md5WithRSA, NID_md5, NID_rsa},
    {NID_dsaWithSHA1, NID_sha1, NID_dsa},
    {NID_sha1WithRSA, NID_sha1, NID_rsa},
    {NID_ripemd160WithRSA, NID_ripemd160, NID_rsaEncryption},
    {NID_md4WithRSAEncryption, NID_md4, NID_rsaEncryption},
    {NID_ecdsa_with_SHA1, NID_sha1, NID_X9_62_id_ecPublicKey},
    {NID_sha256WithRSAEncryption, NID_sha256, NID_rsaEncryption},
    {NID_sha384WithRSAEncryption, NID_sha384, NID_rsaEncryption},
    {NID_sha512WithRSAEncryption, NID_sha512, NID_rsaEncryption},
    {NID_sha224WithRSAEncryption, NID_sha224, NID_rsaEncryption},
    {NID_ecdsa_with_Recommended, NID_undef, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_Specified, NID_undef, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_SHA224, NID_sha224, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_SHA256, NID_sha256, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_SHA384, NID_sha384, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_SHA512, NID_sha512, NID_X9_62_id_ecPublicKey},
    {NID_dsa_with_SHA224, NID_sha224, NID_dsa},
    {NID_dsa_with_SHA256, NID_sha256, NID_dsa},
    {NID_id_GostR3411_94_with_GostR3410_2001, NID_id_GostR3411_94,
     NID_id_GostR3410_2001},
    {NID_id_GostR3411_94_with_GostR3410_94, NID_id_GostR3411_94,
     NID_id_GostR3410_94},
    {NID_id_GostR3411_94_with_GostR3410_94_cc, NID_id_GostR3411_94,
     NID_id_GostR3410_94_cc},
    {NID_id_GostR3411_94_with_GostR3410_2001_cc, NID_id_GostR3411_94,
     NID_id_GostR3410_2001_cc},
};

static int OBJ_find_sigid_algs(int alg, int *hash, int *sig)
{
	unsigned i;

	for (i=0; i< ARRAY_SIZE(sigoid_srt); i++) {
		if (sigoid_srt[i].alg == alg) {
			if (hash)
				*hash = sigoid_srt[i].hash;
			if (sig)
				*sig = sigoid_srt[i].sig;
			return 1;
		}
	}
	return 0;
}
#endif

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
