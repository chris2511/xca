/* vi: set sw=4 ts=4:
 *
 * Regression test: creating a certificate with an ML-KEM key must fail
 * gracefully. The new certificate used to be freed twice (once before the
 * throw, once in the catch handler), which corrupted the heap and made the
 * application die or hang after showing the error message.
 */

#include <QTest>
#include <QFile>

#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/ExportDialog.h"
#include "ui_ExportDialog.h"
#include "ui_NewX509.h"
#include "lib/db_x509.h"
#include "lib/db_key.h"
#include "lib/exception.h"
#include "lib/pki_evp.h"
#include "lib/x509name.h"
#include "lib/xfile.h"

#include "main.h"

#if defined(EVP_PKEY_ML_DSA_65) || defined(NID_ML_KEM_768)
/* Return the inner privateKey of an unencrypted PKCS#8 PEM */
static QByteArray pkcs8Inner(const QString &pem, QByteArray *der = nullptr)
{
	QString body = pem.section("-----END", 0, 0);
	body.remove("-----BEGIN PRIVATE KEY-----");
	body.remove('\n');
	const QByteArray ba = QByteArray::fromBase64(body.toLatin1());
	if (der)
		*der = ba;
	const unsigned char *p = (const unsigned char *)ba.constData();
	PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, ba.size());
	if (!p8)
		return QByteArray();
	const unsigned char *pk = NULL;
	int len = 0;
	QByteArray inner;
	if (PKCS8_pkey_get0(NULL, &pk, &len, NULL, p8))
		inner = QByteArray((const char *)pk, len);
	PKCS8_PRIV_KEY_INFO_free(p8);
	return inner;
}

#ifdef EVP_PKEY_ML_DSA_65
/* Export a key with the given format and return the raw file content */
static QByteArray exportedData(db_key *keys, pki_key *key,
				const pki_export *xport, const QString &fname)
{
	QModelIndexList list;
	list << keys->index(key);
	XFile file(fname);
	file.open_write();
	keys->exportItems(list, xport, file);
	file.close();

	QFile f(fname);
	if (!f.open(QIODevice::ReadOnly))
		return QByteArray();
	const QByteArray ba = f.readAll();
	f.close();
	QFile::remove(fname);
	return ba;
}
#endif
#endif

void test_main::mlkemSigning()
{
#ifndef NID_ML_KEM_768
	QSKIP("ML-KEM is not supported by this OpenSSL version");
#else
	ign_openssl_error();
	openDB();

	db_key *keys = Database.model<db_key>();
	pki_key *key = keys->newKey(keyjob("ML-KEM-768"), "kemkey");
	QVERIFY(key);
	QVERIFY(key->supportsSigning() == false);
	QVERIFY(key->possibleHashNids().isEmpty());

	NewX509 *dlg = new NewX509(mainwin);
	dlg->setCert();
	dlg->show();
	QVERIFY(QTest::qWaitForWindowActive(dlg));

	dlg->keyList->setCurrentPkiItem(key);
	x509name n;
	n.addEntryByNid(NID_commonName, "kemcert");
	dlg->setX509name(n);
	dlg->description->setText("kemcert");

	db_x509 *certs = Database.model<db_x509>();
	pki_x509 *cert = certs->newCert(dlg);

	/* Must be refused, and the object must be destroyed exactly once */
	QVERIFY(cert == nullptr);
	delete dlg;
	QVERIFY(certs->getByName("kemcert") == nullptr);

	/* The database must still be usable afterwards */
	QVERIFY(Database.isOpen());
	QCOMPARE(Store.getAll<pki_base>().size(), 1);
#endif
}

void test_main::pqcClipboardPem()
{
#ifndef EVP_PKEY_ML_DSA_65
	QSKIP("ML-DSA is not supported by this OpenSSL version");
#else
	ign_openssl_error();
	openDB();

	db_key *keys = Database.model<db_key>();
	pki_key *key = keys->newKey(keyjob("ML-DSA-65"), "mldsa-clp");
	QVERIFY(key);
	QVERIFY(key->isPostQuantum());

	/* "PEM private" asks for a traditional key, which does not exist
	 * for PQC. It must fall back to an unencrypted PKCS#8 key. */
	const pki_export *priv = pki_export::by_id(20);
	QVERIFY(priv);
	BioByteArray b;
	QVERIFY(key->pem(b, priv));
	const QString pem = b.qstring();
	qDebug() << "PQC clipboard PEM header:" << pem.left(40);
	QVERIFY2(pem.startsWith("-----BEGIN PRIVATE KEY-----"),
		qPrintable(pem.left(60)));
	QVERIFY(!pem.contains("ML-DSA"));

	/* The exported text must be importable again */
	pki_evp imported;
	imported.fromPEMbyteArray(pem.toUtf8(), "reimported");
	QVERIFY(imported.isPrivKey());
	QVERIFY(imported.isPostQuantum());

	/* "PEM + PKCS#8" is F_PEM|F_PKCS8|F_CRYPT and must be encrypted
	 * PKCS#8, not a traditional key. */
	const pki_export *pk8 = pki_export::by_id(7);
	QVERIFY(pk8);
	BioByteArray be;
	QVERIFY(key->pem(be, pk8));
	QVERIFY2(be.qstring().startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
		qPrintable(be.qstring().left(60)));

	/* The encrypted PKCS#8 must contain the same key and must be
	 * readable with the database password used for encryption. */
	{
		const QByteArray enc = be.byteArray();
		BIO *bio = BIO_new_mem_buf(enc.constData(), enc.size());
		EVP_PKEY *back = PEM_read_bio_PrivateKey(bio, NULL, NULL,
					(void *)pki_evp::passwd.constData());
		BIO_free(bio);
		QVERIFY(back);
		QVERIFY(EVP_PKEY_eq(back, key->getPubKey()) == 1);
		EVP_PKEY_free(back);

		/* Re-import through XCA, asking for the password */
		pwdialog->setExpectations(QList<pw_expect *>{
			new pw_expect("testdbpass", pw_ok),
			new pw_expect("testdbpass", pw_ok),
		});
		pki_evp importedEnc;
		importedEnc.fromPEMbyteArray(enc, "reimported-encrypted");
		QVERIFY(importedEnc.isPrivKey());
		QVERIFY(importedEnc.isPostQuantum());
	}

	/* RFC 9881 defines the ML-DSA PKCS#8 privateKey as a CHOICE:
	 * seed-only ([0]), expanded key, or both (SEQUENCE { seed, key }).
	 * This seed-only key (54 byte PKCS#8) must be importable and is
	 * re-exported in the default "seed + expanded" form, because XCA
	 * does not configure ml-dsa.output_formats. */
	static const char seedOnlyPem[] =
		"-----BEGIN PRIVATE KEY-----\n"
		"MDQCAQAwCwYJYIZIAWUDBAMSBCKAIHkkoLmeoYU6extES/AN3k/pEhS/z6ouP0Eq\n"
		"Hi5qyQQB\n"
		"-----END PRIVATE KEY-----\n";
	pki_evp seedKey;
	seedKey.fromPEMbyteArray(QByteArray(seedOnlyPem), "seed-only");
	QVERIFY(seedKey.isPrivKey());
	QVERIFY(seedKey.isPostQuantum());
	QCOMPARE(seedKey.getTypeString(), QString("ML-DSA-65"));

	BioByteArray bs;
	QVERIFY(seedKey.pem(bs, priv));
	const QString seedPem = bs.qstring();
	QVERIFY(seedPem.startsWith("-----BEGIN PRIVATE KEY-----"));
	QString body = seedPem.section("-----END", 0, 0);
	body.remove("-----BEGIN PRIVATE KEY-----");
	body.remove('\n');
	const QByteArray der = QByteArray::fromBase64(body.toLatin1());
	const unsigned char *derp = (const unsigned char *)der.constData();
	PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &derp, der.size());
	QVERIFY(p8);
	const unsigned char *pk = NULL;
	int pklen = 0;
	QVERIFY(PKCS8_pkey_get0(NULL, &pk, &pklen, NULL, p8));
	QVERIFY(pklen > 0);
	/* SEQUENCE => seed + expanded key, not seed-only or expanded-only */
	QCOMPARE((int)pk[0], 0x30);
	PKCS8_PRIV_KEY_INFO_free(p8);

	/* Type and format capabilities of a PQC key */
	QCOMPARE(key->getTypeString(), QString("ML-DSA-65"));
	QVERIFY(!key->SSH2_compatible());
	QVERIFY(key->possibleHashNids().contains(NID_undef));
	{
		int flags = keys->exportFlags(keys->index(key));
		QVERIFY2(flags & F_PVK, "PVK is not possible for PQC keys");
		QVERIFY2(flags & F_SSH2, "SSH2 is not possible for PQC keys");
		QVERIFY2(flags & F_JWK, "JWK is not possible for PQC keys");
		QVERIFY2(flags & F_TRADITION, "There is no traditional PQC format");
	}

	/* "PEM encrypted" asks for a traditional encrypted key. PQC keys
	 * still have to use PKCS#8, but encryption must be honored. */
	const pki_export *crypt = pki_export::by_id(21);
	QVERIFY(crypt);
	BioByteArray bc;
	QVERIFY(key->pem(bc, crypt));
	QVERIFY2(bc.qstring().startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
		qPrintable(bc.qstring().left(60)));

	/* A classic key must still be exported as encrypted traditional
	 * PEM, i.e. F_CRYPT is honored by the traditional branch as well. */
	pki_key *rsa = keys->newKey(keyjob("RSA:1024"), "rsa-clp");
	QVERIFY(rsa);
	BioByteArray br;
	QVERIFY(rsa->pem(br, crypt));
	const QString rsapem = br.qstring();
	QVERIFY2(rsapem.startsWith("-----BEGIN RSA PRIVATE KEY-----"),
		qPrintable(rsapem.left(60)));
	QVERIFY(rsapem.contains("DEK-Info: AES-256-CBC"));

	/* A private format must not be satisfied by a public key. */
	QByteArray pubba = key->i2d();
	pki_evp pubkey;
	pubkey.d2i(pubba);
	QVERIFY(pubkey.isPubKey());
	bool refused = false;
	try {
		BioByteArray bp;
		pubkey.pem(bp, priv);
	} catch (errorEx &) {
		refused = true;
	}
	QVERIFY2(refused, "Public key must not be exported as private key");
#endif
}

/* The PKCS#8 form of ML-DSA / ML-KEM private keys is chosen by the
 * export format, which selects the provider parameter
 * ml-dsa.output_formats / ml-kem.output_formats. Verify all three forms,
 * the restoration of the parameter and keys without a stored seed. */
void test_main::pqcOutputFormats()
{
#ifndef EVP_PKEY_ML_DSA_65
	QSKIP("ML-DSA is not supported by this OpenSSL version");
#else
	ign_openssl_error();
	openDB();

	db_key *keys = Database.model<db_key>();
	pki_key *key = keys->newKey(keyjob("ML-DSA-65"), "mldsa-fmt");
	QVERIFY(key);
	QVERIFY(key->isPostQuantum());

	/* 29 is the default form: seed and expanded key */
	const pki_export *def = pki_export::by_id(29);
	const pki_export *seedOnly = pki_export::by_id(60);
	const pki_export *seedOnlyEnc = pki_export::by_id(61);
	const pki_export *expanded = pki_export::by_id(62);
	const pki_export *expandedEnc = pki_export::by_id(63);
	QVERIFY(def && seedOnly && seedOnlyEnc && expanded && expandedEnc);

	QCOMPARE(def->pqc, pqcDefault);
	QCOMPARE(seedOnly->pqc, pqcSeedOnly);
	QCOMPARE(seedOnlyEnc->pqc, pqcSeedOnly);
	QCOMPARE(expanded->pqc, pqcExpanded);
	QCOMPARE(expandedEnc->pqc, pqcExpanded);
	QVERIFY(seedOnly->match_all(F_PQC | F_CLIPBOARD | F_PKCS8 | F_PRIVATE));
	QVERIFY(expanded->match_all(F_PQC | F_CLIPBOARD | F_PKCS8 | F_PRIVATE));

	/* default: seed and expanded key */
	BioByteArray b0;
	QVERIFY(key->pem(b0, def));
	QByteArray d0, i0 = pkcs8Inner(b0.qstring(), &d0);
	QVERIFY(!i0.isEmpty());
	QCOMPARE((int)i0.at(0), 0x30);

	/* seed only: [0] with the 32 byte seed, 54 byte PKCS#8 */
	BioByteArray b1;
	QVERIFY(key->pem(b1, seedOnly));
	QByteArray d1, i1 = pkcs8Inner(b1.qstring(), &d1);
	QVERIFY(!i1.isEmpty());
	QCOMPARE((int)(unsigned char)i1.at(0), 0x80);
	QCOMPARE(i1.size(), 34);
	QCOMPARE(d1.size(), 54);

	/* the encrypted variant is still an encrypted PKCS#8 key */
	BioByteArray b1e;
	QVERIFY(key->pem(b1e, seedOnlyEnc));
	QVERIFY2(b1e.qstring().startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
		qPrintable(b1e.qstring().left(60)));

	/* the seed-only key must be importable again */
	pki_evp seedBack;
	seedBack.fromPEMbyteArray(b1.qstring().toUtf8(), "seed-only-rt");
	QVERIFY(seedBack.isPostQuantum());
	QVERIFY(seedBack.isPrivKey());

	/* the file export uses the selected format as well */
	{
		QModelIndexList list;
		list << keys->index(key);
		XFile file("testdata/PQCSEEDONLY.data");
		file.open_write();
		keys->exportItems(list, seedOnly, file);
		file.close();

		QFile exported("testdata/PQCSEEDONLY.data");
		QVERIFY(exported.open(QIODevice::ReadOnly));
		const QString filePem = QString::fromLatin1(exported.readAll());
		exported.close();
		QByteArray fileDer, fileInner = pkcs8Inner(filePem, &fileDer);
		QVERIFY(!fileInner.isEmpty());
		QCOMPARE((int)(unsigned char)fileInner.at(0), 0x80);
		QCOMPARE(fileDer.size(), 54);
	}

	/* expanded key only */
	BioByteArray b2;
	QVERIFY(key->pem(b2, expanded));
	QByteArray d2, i2 = pkcs8Inner(b2.qstring(), &d2);
	QVERIFY(!i2.isEmpty());
	QCOMPARE((int)i2.at(0), 0x04);
	QVERIFY(i2.size() > 4000);
	QVERIFY(d2.size() < d0.size());

	BioByteArray b2e;
	QVERIFY(key->pem(b2e, expandedEnc));
	QVERIFY2(b2e.qstring().startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
		qPrintable(b2e.qstring().left(60)));

	/* "DER private" has no traditional form for PQC keys and falls
	 * back to the default PKCS#8 encoding */
	const pki_export *derDefault = pki_export::by_id(25);
	QVERIFY(derDefault);
	QByteArray der0 = exportedData(keys, key, derDefault, "testdata/PQCDER0.der");
	QVERIFY(!der0.isEmpty());
	QVERIFY(der0.size() > 4000);
	const unsigned char *d0p = (const unsigned char *)der0.constData();
	PKCS8_PRIV_KEY_INFO *p80 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &d0p, der0.size());
	QVERIFY2(p80, "PQC DER export must be a PKCS#8 structure");
	const unsigned char *pk0 = NULL;
	int pk0len = 0;
	QVERIFY(PKCS8_pkey_get0(NULL, &pk0, &pk0len, NULL, p80));
	QCOMPARE((int)(unsigned char)pk0[0], 0x30);	/* seed + expanded key */
	PKCS8_PRIV_KEY_INFO_free(p80);

	/* The other two seed forms are available as binary DER as well */
	const pki_export *derSeedOnly = pki_export::by_id(65);
	const pki_export *derExpanded = pki_export::by_id(66);
	QVERIFY(derSeedOnly && derExpanded);

	QByteArray der1 = exportedData(keys, key, derSeedOnly, "testdata/PQCDER1.der");
	QVERIFY(!der1.isEmpty());
	QCOMPARE(der1.size(), 54);
	const unsigned char *d1p = (const unsigned char *)der1.constData();
	PKCS8_PRIV_KEY_INFO *p8d = d2i_PKCS8_PRIV_KEY_INFO(NULL, &d1p, der1.size());
	QVERIFY(p8d);
	const unsigned char *pkd = NULL;
	int pkdlen = 0;
	QVERIFY(PKCS8_pkey_get0(NULL, &pkd, &pkdlen, NULL, p8d));
	QCOMPARE((int)(unsigned char)pkd[0], 0x80);
	PKCS8_PRIV_KEY_INFO_free(p8d);

	QByteArray der2 = exportedData(keys, key, derExpanded, "testdata/PQCDER2.der");
	QVERIFY(!der2.isEmpty());
	const unsigned char *d2p = (const unsigned char *)der2.constData();
	PKCS8_PRIV_KEY_INFO *p8e = d2i_PKCS8_PRIV_KEY_INFO(NULL, &d2p, der2.size());
	QVERIFY(p8e);
	const unsigned char *pke = NULL;
	int pkelen = 0;
	QVERIFY(PKCS8_pkey_get0(NULL, &pke, &pkelen, NULL, p8e));
	QCOMPARE((int)(unsigned char)pke[0], 0x04);
	PKCS8_PRIV_KEY_INFO_free(p8e);

	/* back to the default: the provider parameter must be restored */
	BioByteArray b3;
	QVERIFY(key->pem(b3, def));
	QByteArray i3 = pkcs8Inner(b3.qstring());
	QVERIFY(!i3.isEmpty());
	QCOMPARE((int)i3.at(0), 0x30);
	QCOMPARE(b3.size(), b0.size());

	/* A key imported from the expanded form has no seed: the default
	 * falls back to the expanded key, "seed only" must be refused. */
	pki_evp expandedKey;
	expandedKey.fromPEMbyteArray(b2.qstring().toUtf8(), "expanded-rt");
	QVERIFY(expandedKey.isPostQuantum());

	BioByteArray b4;
	QVERIFY(expandedKey.pem(b4, def));
	QByteArray i4 = pkcs8Inner(b4.qstring());
	QVERIFY(!i4.isEmpty());
	QCOMPARE((int)i4.at(0), 0x04);

	bool refusedSeed = false;
	try {
		BioByteArray b5;
		expandedKey.pem(b5, seedOnly);
	} catch (errorEx &) {
		refusedSeed = true;
	}
	QVERIFY2(refusedSeed, "seed-only export of a seedless key must fail");

#ifdef NID_ML_KEM_768
	/* ML-KEM uses its own provider parameter, but the same forms */
	pki_key *kem = keys->newKey(keyjob("ML-KEM-768"), "mlkem-fmt");
	QVERIFY(kem);
	QVERIFY(kem->hasSeedFormat());
	BioByteArray bk;
	QVERIFY(kem->pem(bk, seedOnly));
	QByteArray dk, ik = pkcs8Inner(bk.qstring(), &dk);
	QVERIFY(!ik.isEmpty());
	QCOMPARE((int)(unsigned char)ik.at(0), 0x80);
	QCOMPARE(ik.size(), 66);	/* 64 byte seed */
	QCOMPARE(dk.size(), 86);
	BioByteArray bk2;
	QVERIFY(kem->pem(bk2, expanded));
	QByteArray ik2 = pkcs8Inner(bk2.qstring());
	QVERIFY(!ik2.isEmpty());
	QCOMPARE((int)ik2.at(0), 0x04);
#endif
#endif
}

#if defined(NID_ML_KEM_768) && defined(EVP_PKEY_ML_DSA_65)
/* IDs of the export formats offered for a key selection */
static QList<int> selectedFormats(db_base *keys, const QModelIndexList &list)
{
	QList<int> ids;
	foreach (const pki_export *x, pki_export::select(asym_key,
						keys->exportFlags(list)))
		ids << x->id;
	return ids;
}

/* Export dialog set up the same way as the key tree view does it */
static ExportDialog *exportDialogFor(db_base *keys, const QModelIndexList &list)
{
	return new ExportDialog(mainwin, QString(), QString(), list, QPixmap(),
			pki_export::select(asym_key, keys->exportFlags(list)));
}
#endif

/* The seed based PKCS#8 formats only exist for the lattice based
 * ML-DSA and ML-KEM private keys. Keys without such a format must not
 * offer them and must not offer a traditional PEM format either. */
void test_main::pqcSeedFormatSelection()
{
	QVERIFY(isPqcSeedName("ML-DSA-65"));
	QVERIFY(isPqcSeedName("ML-KEM-768"));
	QVERIFY(!isPqcSeedName("SLH-DSA-SHA2-128s"));
	QVERIFY(!isPqcSeedName("SLH-DSA-SHAKE-128f"));
	QVERIFY(!isPqcSeedName("RSA"));
	QVERIFY(!isPqcSeedName("ED25519"));

#if defined(NID_ML_KEM_768) && defined(EVP_PKEY_ML_DSA_65)
	ign_openssl_error();
	openDB();

	db_key *keys = Database.model<db_key>();
	pki_key *kem = keys->newKey(keyjob("ML-KEM-768"), "kem-seedfmt");
	QVERIFY(kem);
	QVERIFY(kem->hasSeedFormat());

	/* The PEM and DER formats are kept and fall back to PKCS#8, the
	 * other two seed based forms are offered additionally */
	QModelIndexList list;
	list << keys->index(kem);
	QList<int> ids = selectedFormats(keys, list);
	QVERIFY2(ids.contains(20), "PEM private format missing for a PQC key");
	QVERIFY2(ids.contains(25), "DER private format missing for a PQC key");
	QVERIFY2(ids.contains(29), "default PKCS#8 format missing");
	QVERIFY2(ids.contains(60), "seed only PKCS#8 format missing");
	QVERIFY2(ids.contains(61), "encrypted seed only PKCS#8 format missing");
	QVERIFY2(ids.contains(62), "expanded PKCS#8 format missing");
	QVERIFY2(ids.contains(63), "encrypted expanded PKCS#8 format missing");
	QVERIFY2(ids.contains(65), "seed only PKCS#8 DER format missing");
	QVERIFY2(ids.contains(66), "expanded PKCS#8 DER format missing");
	QVERIFY2(!ids.contains(21), "traditional encrypted PEM for a PQC key");

	/* The export dialog offers exactly this list of formats */
	ExportDialog *dlg = exportDialogFor(keys, list);
	bool hasSeedOnly = false, hasPemPrivate = false;
	for (int i = 0; i < dlg->exportFormat->count(); i++) {
		int id = dlg->exportFormat->itemData(i).toInt();
		hasSeedOnly = hasSeedOnly || id == 60;
		hasPemPrivate = hasPemPrivate || id == 20;
	}
	QVERIFY2(hasSeedOnly, "seed only format missing in the export dialog");
	QVERIFY2(hasPemPrivate, "PEM private format missing in the export dialog");
	delete dlg;

	/* A public key has no private format at all */
	QByteArray pubba = kem->i2d();
	pki_evp pubkey;
	pubkey.d2i(pubba);
	QVERIFY(pubkey.isPubKey());
	QVERIFY(!pubkey.hasSeedFormat());

	/* SLH-DSA is post quantum, but has no seed based encoding */
#ifdef EVP_PKEY_SLH_DSA_SHA2_128S
	pki_key *slh = keys->newKey(keyjob("SLH-DSA-SHA2-128s"), "slh-seedfmt");
	QVERIFY(slh);
	QVERIFY(slh->isPostQuantum());
	QVERIFY(!slh->hasSeedFormat());
	QModelIndexList slhList;
	slhList << keys->index(slh);
	ids = selectedFormats(keys, slhList);
	QVERIFY2(ids.contains(29), "PKCS#8 format missing for SLH-DSA");
	QVERIFY2(!ids.contains(60), "seed format offered for SLH-DSA");
	QVERIFY2(!ids.contains(62), "expanded format offered for SLH-DSA");
	QVERIFY2(!ids.contains(65), "seed DER format offered for SLH-DSA");
	QVERIFY2(!ids.contains(66), "expanded DER format offered for SLH-DSA");
#endif

	/* Classic keys keep the traditional formats and get no PQC forms */
	pki_key *rsa = keys->newKey(keyjob("RSA:1024"), "rsa-seedfmt");
	QVERIFY(rsa);
	QVERIFY(!rsa->hasSeedFormat());
	QModelIndexList rsaList;
	rsaList << keys->index(rsa);
	ids = selectedFormats(keys, rsaList);
	QVERIFY2(ids.contains(20), "traditional PEM private missing for RSA");
	QVERIFY2(ids.contains(25), "traditional DER private missing for RSA");
	QVERIFY2(ids.contains(29), "PKCS#8 format missing for RSA");
	QVERIFY2(!ids.contains(60), "seed format offered for RSA");
	QVERIFY2(!ids.contains(62), "expanded format offered for RSA");
	QVERIFY2(!ids.contains(65), "seed DER format offered for RSA");

	/* Classic keys keep the traditional DER encoding: "DER private"
	 * is a PKCS#1 / SEC1 structure, not PKCS#8 */
	QByteArray rsaDer = exportedData(keys, rsa, pki_export::by_id(25),
					"testdata/RSADER.der");
	QVERIFY(!rsaDer.isEmpty());
	const unsigned char *rsap = (const unsigned char *)rsaDer.constData();
	PKCS8_PRIV_KEY_INFO *rsap8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &rsap,
							rsaDer.size());
	QVERIFY2(!rsap8, "traditional RSA DER is not a PKCS#8 structure");
	rsap = (const unsigned char *)rsaDer.constData();
	RSA *rsaKey = d2i_RSAPrivateKey(NULL, &rsap, rsaDer.size());
	QVERIFY2(rsaKey, "traditional RSA DER must be a PKCS#1 structure");
	RSA_free(rsaKey);
#endif
}
