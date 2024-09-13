/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2024 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QDir>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "lib/pki_multi.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_temp.h"
#include "lib/xfile.h"
#include "lib/database_model.h"

#include <widgets/MainWindow.h>
#include "main.h"

void check_pems(const QString &name, int n, QStringList matches = QStringList())
{
	int begin = 0, end = 0;
	qDebug() << "Expecting" << n << "PEMs in" << name;

#if 0
	// This is an endless loop: open_read() succeeds,
	// but isOpen returns false. Stop investigating, use POSIX open()
	XFile F(name);
	while (!F.isOpen()) {
		qDebug() << "OPEN" << name;
		F.close();
		Q_ASSERT(F.open_read());
	}
	QByteArray all = F.readAll();
#else
	int fd = open(qPrintable(name), O_RDONLY);
	Q_ASSERT(fd != -1);
	char buf[65536];
	ssize_t ret = read(fd, buf, sizeof buf);
	Q_ASSERT(ret != -1);
	QByteArray all(buf, ret);
	close(fd);
#endif
	qDebug() << "ALL" << name << all.size();

	foreach(QByteArray b, all.split('\n')) {
		if (b.indexOf("-----BEGIN ") == 0)
			begin++;
		if (b.indexOf("-----END ") == 0)
			end++;

		QMutableStringListIterator i(matches);
		while (i.hasNext()) {
			QByteArray match = i.next().toUtf8();
			if (b.indexOf(match) != -1)
				i.remove();
		}
    }
	QCOMPARE(begin, n);
	QCOMPARE(end, n);
	foreach(QString m, matches) {
		qDebug() << QString("Pattern %1 not found in %2").arg(m).arg(name);
	}
	QCOMPARE(matches.size(), 0);
}

void verify_key(const QString &name, QList<unsigned> hashes, bool priv)
{
	pki_multi *pems = new pki_multi();
	QVERIFY(pems != nullptr);
	pems->probeAnything(name);
	QCOMPARE(pems->get().size(), hashes.size());
	foreach (pki_base *pki, pems->get()) {
		unsigned hash = pki->hash();
		qDebug() << pki->getIntName() << hash;
		QVERIFY2(hashes.contains(hash),
			qPrintable(QString("%1 not expected in %2 (%3)")
				.arg(pki->getIntName())
				.arg(name).arg(hash)
			)
		);
		pki_key *key = dynamic_cast<pki_key*>(pki);
		if (key) {
			QCOMPARE(key->isPrivKey(), priv);
		}
	}
}

void verify_file(const QString &name, QList<unsigned> hashes)
{
	verify_key(name, hashes, false);
}

void verify_template(const QString &name)
{
	pki_multi *pems = new pki_multi();
	pems->probeAnything(name);
	QList<pki_base *> temps = pems->pull();
	QCOMPARE(temps.size(), 1);
	pki_temp *temp = dynamic_cast<pki_temp*>(temps[0]);
	QVERIFY(temp != nullptr);
	QCOMPARE(temp->getIntName(), "My Template Internal Name");
	QCOMPARE(temp->getComment(), "My XCA TEMPLATE comment");
	x509name xn = temp->getSubject();
	QCOMPARE(xn.getEntryByNid(NID_commonName), "CA Template");
	QCOMPARE(xn.getEntryByNid(NID_pkcs9_emailAddress), "mail@address.to");
}

QJsonValue jsonFromFile(const QString &name)
{
	QFile file(name);
	if (file.open(QIODevice::ReadOnly)) {
		QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
		return doc.object();
	}
	return QJsonValue();
}

QString urldecode(const QJsonValue &in)
{
	if (!in.isString())
		return QString();
	QByteArray ba = in.toString().toLatin1();
	return QByteArray::fromBase64(ba,
			QByteArray::Base64UrlEncoding).toHex(':').toUpper();
}

void export_by_id(int id, const QString &name,
				QModelIndexList &list, db_base *db)
{
	const pki_export *xport = pki_export::by_id(id);
	QVERIFY(xport != nullptr);
	XFile F(name);
	F.open_write();
	if (xport->match_all(F_PEM)) {
		QString prefix = QString("%1\n").arg(xport->help);
		foreach (QModelIndex idx, list) {
			pki_base *pki = db_base::fromIndex(idx);
			QVERIFY(pki != nullptr);
			prefix += QString(" - %1[%2]\n")
					.arg(pki->getIntName())
					.arg(pki->getTypeString());
		}
		F.write(prefix.toUtf8());
	}
	db->exportItems(list, xport, F);
	F.close();
}

void test_main::exportFormat()
{
	int l=0;
	QModelIndex idx;
	QModelIndexList list;
	QDir d; d.mkpath("testdata");

	try {

	ign_openssl_error();
	openDB();
	dbstatus();
	pki_multi *pem = new pki_multi();
	QString all = pemdata["Inter CA 1"] +
				pemdata["Inter CA 1 Key"] +
				pemdata["Root CA"] +
				pemdata["Endentity"] +
				pemdata["CA CRL Test"] +
				pemdata["XCA Template"] +
				pemdata["SECP-521"];

	pem->fromPEMbyteArray(all.toUtf8(), QString());
	QCOMPARE(pem->failed_files.count(), 0);
	Database.insert(pem);
	dbstatus();

	db_base *certs = Database.model<db_x509>();
	QVERIFY(certs != nullptr);

	// Root CA as only item: No chain, no private key
	idx = certs->index(certs->getByName("Root CA"));
	list << idx;
	QCOMPARE(certs->exportFlags(idx) , F_CHAIN | F_PRIVATE);
	QCOMPARE(certs->exportFlags(list) , F_CHAIN | F_PRIVATE);

	// Inter CA 1: All export options permitted
	// Together with "Root CA" in "list": No chain, private or single
	idx = certs->index(certs->getByName("Inter CA 1"));
	list << idx;
	QCOMPARE(certs->exportFlags(idx) , 0);
	QCOMPARE(certs->exportFlags(list) , F_CHAIN | F_PRIVATE);

	// Endentity has no private key and id no CA
	idx = certs->index(certs->getByName("Endentity"));
	list << idx;
	QVERIFY(idx.isValid());
	QCOMPARE(certs->exportFlags(idx) , F_PRIVATE | F_CA);

	pki_key *key = new pki_evp();
	key->fromPEMbyteArray(pemdata["Endentity Key"].toUtf8(), QString());
	openssl_error();
	Database.insert(key);
	dbstatus();

	// Endentity now has a private key, but is still no CA
	QCOMPARE(certs->exportFlags(idx) , F_CA);

#define ROOT_HASH 531145749
#define INTER_HASH 376625776
#define END_HASH 94304590
#define EXPIRED_HASH 1359605174
#define ENDKEY_HASH 1121702347
#define ED25519_HASH 318722247

#define xstr(s) str(s)
#define str(s) #s
#define AUTOFILE(type) "testdata/" # type "_Line" xstr(__LINE__) ".data" ;

	const char *file = AUTOFILE(ALLCERT)
	// Export All certs in one PEM File
	export_by_id(3, file, list, certs);
	verify_file(file, QList<unsigned> { ROOT_HASH, INTER_HASH, END_HASH });
	check_pems(file, 3);
	// Export 2 cert Chain from Inter CA1
	file = AUTOFILE(CERTCHAIN)
	list.clear();
	list << certs->index(certs->getByName("Inter CA 1"));
	export_by_id(2, file, list, certs);
	verify_file(file, QList<unsigned> { ROOT_HASH, INTER_HASH });
	check_pems(file, 2);

	// Export 3 cert Chain from Endentity
	file = AUTOFILE(CERTCHAIN)
	list.clear();
	list << certs->index(certs->getByName("Endentity"));
	export_by_id(2, file, list, certs);
	verify_file(file, QList<unsigned> { ROOT_HASH, INTER_HASH, END_HASH });
	check_pems(file, 3);

	// Export Endentity + corresponding key
	file = AUTOFILE(CERTKEY)
	export_by_id(6, file, list, certs);
	verify_key(file, QList<unsigned> { END_HASH, ENDKEY_HASH }, true);
	check_pems(file, 2, QStringList { " RSA PRIVATE KEY-", " CERTIFICATE-" });

	// Export Endentity + corresponding PKCS#8 key
	file = AUTOFILE(CERTPK8)
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("pass", pw_ok),
		new pw_expect("pass", pw_ok),
	});
	export_by_id(7, file, list, certs);
	verify_key(file, QList<unsigned> { END_HASH, ENDKEY_HASH }, true);
	check_pems(file, 2, QStringList { " ENCRYPTED PRIVATE KEY-", " CERTIFICATE-" });
	// Export OpenVPN format
	file = AUTOFILE(OPENVPN)
	export_by_id(4, file, list, certs);
	verify_key(file, QList<unsigned> {
			ROOT_HASH, INTER_HASH, END_HASH, ENDKEY_HASH }, true);
	check_pems(file, 5, QStringList { " RSA PRIVATE KEY-",
		" CERTIFICATE-", " CERTIFICATE-"," CERTIFICATE-",
		"<ca>", "</ca>", "<extra-certs>", "</extra-certs>",
		"<cert>", "</cert>", "<key>", "</key>",
		"<tls-auth>", "</tls-auth>" });
	// Export Endentity as PKCS#7
	file = AUTOFILE(CERTP7)
	export_by_id(8, file, list, certs);
	verify_file(file, QList<unsigned> {  END_HASH });
	check_pems(file, 0);
	// Export Endentity as PKCS#7 chain
	file = AUTOFILE(CERTP7)
	export_by_id(12, file, list, certs);
	verify_file(file, QList<unsigned> { ROOT_HASH, INTER_HASH, END_HASH });
	check_pems(file, 0);
	// Export Endentity as DER certificate
	file = AUTOFILE(CERTDER)
	export_by_id(13, file, list, certs);
	verify_file(file, QList<unsigned> {  END_HASH });
	check_pems(file, 0);
	// Export Endentity as OpenVPN config file
	file = AUTOFILE(OPENVPNTA)
	export_by_id(39, file, list, certs);
	check_pems(file, 1, QStringList {
		"BEGIN OpenVPN Static key V1", "END OpenVPN Static key V1" });

	// Revoke endentity
	pki_x509 *endentity = dynamic_cast<pki_x509*>(certs->getByName("Endentity"));
	QVERIFY(endentity != nullptr);
	x509rev rev;
	rev.setSerial(endentity->getSerial());
	rev.setDate(a1time::now());
	endentity->setRevoked(rev);
	QVERIFY(endentity->isRevoked());
	// List must not be empty, but may contain anything
	list.clear();
	list << certs->index(certs->getByName("Inter CA 1"));
	// Export unusable as PEM
	file = AUTOFILE(UNUSABLEPEM)
	export_by_id(40, file, list, certs);
	verify_file(file, QList<unsigned> { END_HASH, EXPIRED_HASH });
	check_pems(file, 2);
	// Once more as PKCS#7
	file = AUTOFILE(UNUSABLEP7)
	export_by_id(41, file, list, certs);
	verify_file(file, QList<unsigned> { END_HASH, EXPIRED_HASH });
	check_pems(file, 0);

	// Export Endentity as JWK
	file = AUTOFILE(JWK)
	list.clear();
	list << certs->index(certs->getByName("Endentity"));
	export_by_id(42, file, list, certs);
	QJsonValue jwk = jsonFromFile(file);
	QVERIFY(jwk.isObject());
	QJsonObject o = jwk.toObject();
	QCOMPARE(o["kty"].toString(), "RSA");
	QCOMPARE(o["kid"].toString(), "Endentity");
	QCOMPARE(urldecode(o["x5t"]), "4E:F9:9E:05:EF:7D:0D:DE:DB:A4:56:D6:86:93:49:11:58:FA:45:73");
	QCOMPARE(urldecode(o["x5t#256"]), "2E:3C:84:81:13:00:0D:41:65:4E:60:B4:52:FA:D1:CB:C0:DF:26:A1:DD:0F:E8:AD:F4:84:24:7B:BF:9B:94:8F");
	QCOMPARE(urldecode(o["n"]), "00:A6:83:93:C4:A8:8A:56:77:1C:E4:62:F4:C9:F8:A7:78:85:3B:8D:E8:7D:A6:CB:17:AF:17:59:D9:EB:82:DB:81:64:E0:E6:2C:05:E2:9C:49:6D:EB:67:9D:19:FA:3D:EB:2C:E1:49:07:41:DC:71:B6:ED:70:D1:C7:18:3E:A1:1F:57:52:55:3F:EC:1E:C1:8D:E4:C9:E4:B5:11:D3:74:12:43:6D:15:0B:CC:8A:7C:3D:BC:79:37:41:B8:3B:43:CD:61:61:72:26:D7:A8:8E:B6:F9:D0:5F:C6:F4:E2:C4:6D:2D:96:45:A8:8D:79:00:12:79:1C:6D:F0:D2:94:58:FE:E8:2E:7A:4F:9F:87:37:DA:C0:A1:FB:03:A5:57:02:59:8D:96:EF:57:2B:78:EE:53:6F:93:37:7A:4E:FD:6F:06:A0:8C:02:3C:CC:93:A7:82:0C:4C:35:15:98:06:27:AD:40:75:36:92:2F:1C:52:EA:3D:20:E7:64:0D:1D:EC:6B:CE:C0:0C:0B:53:90:38:D2:E0:B3:F0:FB:0E:D8:40:31:68:36:67:9B:F3:2D:7A:75:B9:95:B5:53:F4:01:2E:9C:2A:F0:18:69:61:73:20:40:B8:DA:F2:FA:CA:2A:E5:7F:AD:BA:FA:02:1F:54:BC:6E:69:48:79:9F:9D:5C:0F:99");
	QCOMPARE(urldecode(o["e"]), "01:00:01");
	QVERIFY(o["x5c"].isNull());

	file = AUTOFILE(JWK5C)
	list.clear();
	list << certs->index(certs->getByName("Endentity"));
	export_by_id(43, file, list, certs);
	jwk = jsonFromFile(file);
	QVERIFY(jwk.isObject());
	o = jwk.toObject();
	QCOMPARE(o["kty"].toString(), "RSA");
	QCOMPARE(o["kid"].toString(), "Endentity");
	QCOMPARE(urldecode(o["x5t"]), "4E:F9:9E:05:EF:7D:0D:DE:DB:A4:56:D6:86:93:49:11:58:FA:45:73");
	QCOMPARE(urldecode(o["x5t#256"]), "2E:3C:84:81:13:00:0D:41:65:4E:60:B4:52:FA:D1:CB:C0:DF:26:A1:DD:0F:E8:AD:F4:84:24:7B:BF:9B:94:8F");
	QCOMPARE(urldecode(o["n"]), "00:A6:83:93:C4:A8:8A:56:77:1C:E4:62:F4:C9:F8:A7:78:85:3B:8D:E8:7D:A6:CB:17:AF:17:59:D9:EB:82:DB:81:64:E0:E6:2C:05:E2:9C:49:6D:EB:67:9D:19:FA:3D:EB:2C:E1:49:07:41:DC:71:B6:ED:70:D1:C7:18:3E:A1:1F:57:52:55:3F:EC:1E:C1:8D:E4:C9:E4:B5:11:D3:74:12:43:6D:15:0B:CC:8A:7C:3D:BC:79:37:41:B8:3B:43:CD:61:61:72:26:D7:A8:8E:B6:F9:D0:5F:C6:F4:E2:C4:6D:2D:96:45:A8:8D:79:00:12:79:1C:6D:F0:D2:94:58:FE:E8:2E:7A:4F:9F:87:37:DA:C0:A1:FB:03:A5:57:02:59:8D:96:EF:57:2B:78:EE:53:6F:93:37:7A:4E:FD:6F:06:A0:8C:02:3C:CC:93:A7:82:0C:4C:35:15:98:06:27:AD:40:75:36:92:2F:1C:52:EA:3D:20:E7:64:0D:1D:EC:6B:CE:C0:0C:0B:53:90:38:D2:E0:B3:F0:FB:0E:D8:40:31:68:36:67:9B:F3:2D:7A:75:B9:95:B5:53:F4:01:2E:9C:2A:F0:18:69:61:73:20:40:B8:DA:F2:FA:CA:2A:E5:7F:AD:BA:FA:02:1F:54:BC:6E:69:48:79:9F:9D:5C:0F:99");
	QCOMPARE(urldecode(o["e"]), "01:00:01");
	QVERIFY(o["x5c"].isArray());
	QJsonArray x5c = o["x5c"].toArray();
	QCOMPARE(x5c.size(), 3);
	QCOMPARE(x5c[0].toString(), certs->getByName("Endentity")->i2d_b64());
	QCOMPARE(x5c[1].toString(), certs->getByName("Inter CA 1")->i2d_b64());
	QCOMPARE(x5c[2].toString(), certs->getByName("Root CA")->i2d_b64());

	// Export Endentity key
	list.clear();
	key = dynamic_cast<pki_x509*>(certs->getByName("Endentity"))->getRefKey();
	db_base *keys = Database.model<db_key>();
	list << keys->index(key);

	// Public Key
	file = AUTOFILE(PUBKEY)
	export_by_id(19, file, list, keys);
	verify_key(file, QList<unsigned> {  ENDKEY_HASH }, false);
	check_pems(file, 1, QStringList{ "PUBLIC KEY" });

	// Private Key
	file = AUTOFILE(PRIVKEY)
	export_by_id(20, file, list, keys);
	verify_key(file, QList<unsigned> {  ENDKEY_HASH }, true);
	check_pems(file, 1, QStringList{ "RSA PRIVATE KEY" });

	// Private Key Openssl Encrypted
	file = AUTOFILE(PRIVKEY)
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("pass", pw_ok),
		new pw_expect("pass", pw_ok),
	});
	export_by_id(21, file, list, keys);
	verify_key(file, QList<unsigned> {  ENDKEY_HASH }, true);
	check_pems(file, 1, QStringList { "DEK-Info: ", "Proc-Type: 4,ENCRYPTED", "BEGIN RSA PRIVATE KEY" });

	// Private SSH Key
	file = AUTOFILE(PRIVSSH)
	export_by_id(22, file, list, keys);
	verify_key(file, QList<unsigned> {  ENDKEY_HASH }, true);
	check_pems(file, 1, QStringList{ "RSA PRIVATE KEY" });

	// Public SSH Key
	file = AUTOFILE(PUBSSH)
	export_by_id(23, file, list, keys);
	verify_key(file, QList<unsigned> {  ENDKEY_HASH }, false);
	check_pems(file, 0, QStringList{ "ssh-rsa " });

	// Public DER Key
	file = AUTOFILE(PUBDER)
	export_by_id(24, file, list, keys);
	verify_key(file, QList<unsigned> {  ENDKEY_HASH }, false);
	check_pems(file, 0);

	// Private DER Key
	file = AUTOFILE(PRIVDER)
	export_by_id(25, file, list, keys);
	verify_key(file, QList<unsigned> {  ENDKEY_HASH }, true);
	check_pems(file, 0);

	// Private PVK Key
	file = AUTOFILE(PVK)
	export_by_id(26, file, list, keys);
	verify_key(file, QList<unsigned> {  ENDKEY_HASH }, true);
	check_pems(file, 0);

	// Private PVK Key
	file = AUTOFILE(JWK_RSA)
	export_by_id(50, file, list, keys);
	jwk = jsonFromFile(file);
	QVERIFY(jwk.isObject());
	o = jwk.toObject();
	QCOMPARE(o["kty"].toString(), "RSA");
	QCOMPARE(o["kid"].toString(), "2048 bit RSA");
	QCOMPARE(urldecode(o["n"]), "00:A6:83:93:C4:A8:8A:56:77:1C:E4:62:F4:C9:F8:A7:78:85:3B:8D:E8:7D:A6:CB:17:AF:17:59:D9:EB:82:DB:81:64:E0:E6:2C:05:E2:9C:49:6D:EB:67:9D:19:FA:3D:EB:2C:E1:49:07:41:DC:71:B6:ED:70:D1:C7:18:3E:A1:1F:57:52:55:3F:EC:1E:C1:8D:E4:C9:E4:B5:11:D3:74:12:43:6D:15:0B:CC:8A:7C:3D:BC:79:37:41:B8:3B:43:CD:61:61:72:26:D7:A8:8E:B6:F9:D0:5F:C6:F4:E2:C4:6D:2D:96:45:A8:8D:79:00:12:79:1C:6D:F0:D2:94:58:FE:E8:2E:7A:4F:9F:87:37:DA:C0:A1:FB:03:A5:57:02:59:8D:96:EF:57:2B:78:EE:53:6F:93:37:7A:4E:FD:6F:06:A0:8C:02:3C:CC:93:A7:82:0C:4C:35:15:98:06:27:AD:40:75:36:92:2F:1C:52:EA:3D:20:E7:64:0D:1D:EC:6B:CE:C0:0C:0B:53:90:38:D2:E0:B3:F0:FB:0E:D8:40:31:68:36:67:9B:F3:2D:7A:75:B9:95:B5:53:F4:01:2E:9C:2A:F0:18:69:61:73:20:40:B8:DA:F2:FA:CA:2A:E5:7F:AD:BA:FA:02:1F:54:BC:6E:69:48:79:9F:9D:5C:0F:99");
	QCOMPARE(urldecode(o["e"]), "01:00:01");
	QCOMPARE(urldecode(o["d"]), "01:6B:1B:01:E0:96:A7:14:66:2A:5A:DE:6F:6E:FF:0C:33:84:55:99:DE:A2:22:56:3E:0F:52:9C:5C:D9:75:41:B5:A8:85:C5:67:BA:6D:AE:E1:71:11:25:A1:30:44:C1:41:55:5C:F0:23:23:3B:D3:BD:53:89:F1:EA:76:B4:1C:26:7C:04:CE:61:D6:44:3B:4F:70:D9:D2:22:07:FD:53:DF:7F:A9:1F:7B:DB:4D:22:20:7E:1E:D6:A0:39:5F:03:3B:9A:5F:24:CE:0E:F9:42:3D:40:05:64:D6:36:AD:4A:29:CA:7F:26:E7:A7:99:74:CE:D3:CB:6A:F2:FC:41:02:CD:55:AA:24:CB:25:AE:B1:0F:8F:B0:C1:C7:23:B1:18:AF:E0:B5:58:D1:54:C4:28:9B:4E:E0:5C:DB:5F:93:A0:44:EE:E8:D4:96:A5:65:5F:7E:34:CC:F7:E2:F0:E7:2D:C0:AA:B5:D7:8D:E7:A1:3C:9F:31:56:80:D7:95:30:78:0F:8A:28:5B:AF:3F:E7:EA:47:AD:8A:32:E4:EC:32:55:8C:19:15:2B:5E:E4:1F:76:9A:1C:36:F9:53:CB:61:9E:CF:A8:DE:02:29:52:1B:08:78:E0:0C:DC:0F:B3:76:18:51:4C:0C:C9:0F:F2:0B:E5:69:60:96:B9:CD:26:A9:25");
	QCOMPARE(urldecode(o["p"]), "00:D7:D1:5A:40:CC:9F:15:53:79:5D:5B:F1:06:3A:F5:6B:5E:64:A5:4D:AC:86:06:A9:FC:39:30:23:1D:6F:3A:9D:86:7F:B9:89:9E:60:F4:27:B3:87:08:86:94:65:A8:6C:8E:F1:E0:2B:A3:97:69:20:1E:BD:DB:DC:86:41:31:9D:C5:A5:C5:DC:99:99:15:81:63:80:45:B6:8F:D3:C5:B4:B9:68:BD:5D:E6:2C:4A:24:CC:07:95:22:C8:FF:1F:23:08:20:41:04:6A:80:BE:90:56:95:AF:81:F2:6E:C5:9C:42:65:AA:0E:CA:67:BB:26:CA:B7:48:8A:E6:4C:5C:75");
	QCOMPARE(urldecode(o["q"]), "00:C5:84:3A:8F:52:2C:31:52:15:0D:AC:F5:8C:AA:71:DF:68:38:F3:3D:59:13:ED:56:76:AF:21:7C:B0:44:7D:2A:5D:43:13:D9:98:D2:F6:D0:82:22:FC:C7:EB:4D:E6:04:58:CB:AC:7D:D1:B6:25:2C:A1:54:2A:83:EE:F1:CC:EB:26:B1:FE:B7:8F:D9:7B:F7:AE:1F:6E:FE:BC:A7:7F:C3:73:03:A7:83:27:42:D4:F4:D5:CB:13:E7:E6:ED:B1:60:79:49:49:73:B7:A7:D0:BE:4C:3F:A7:29:40:82:52:A9:92:D4:DF:8C:46:8B:A1:57:8B:4E:89:4A:E2:2F:52:15");
	QCOMPARE(urldecode(o["dp"]), "00:A2:29:F0:C3:17:FD:C1:2C:83:D9:1E:A8:B0:A1:C4:9E:F4:C2:73:63:35:EB:4F:3E:93:02:F5:A4:AD:0D:52:E1:E2:9A:3E:73:A5:C9:FC:2B:88:BE:42:2D:BD:7B:D5:5E:1C:DA:AA:32:A0:2D:B9:14:25:85:4B:9B:1C:56:08:4E:20:A1:3B:57:53:22:B0:02:15:1D:E1:44:18:36:6C:2C:2B:D5:03:D5:76:8A:78:FB:C5:43:3D:50:71:EF:21:1A:55:94:C6:C5:E6:B0:EE:7F:CE:4F:93:1C:F5:69:3E:9A:F7:59:24:BB:10:63:79:40:E0:B9:6F:8C:CF:17:39:B1");
	QCOMPARE(urldecode(o["dq"]), "1A:7F:5A:BB:CF:72:4E:4B:8C:B7:80:F4:90:22:6D:94:63:0F:00:D2:C2:18:82:46:8F:35:7F:70:92:D5:1D:55:89:9D:6E:14:4B:04:42:48:46:AD:1A:EC:57:0C:E4:46:C1:02:D1:E9:2F:31:18:5B:9C:69:06:2B:1C:EB:23:6A:88:8E:68:75:87:BE:CD:7A:B4:C9:52:C2:A9:DC:6E:AF:71:C6:93:BA:6C:91:F2:AF:C5:DE:B0:94:F3:CD:FF:75:C9:CF:A3:22:FB:08:70:60:97:2A:12:EA:DD:D4:9D:F2:51:D8:6D:05:0C:91:BE:DB:57:BC:F9:7E:2A:49:DE:E1");
	QCOMPARE(urldecode(o["qi"]), "00:83:14:28:86:46:00:AA:63:07:8C:20:37:D2:8D:D1:EC:CA:CA:DF:C6:76:DF:FF:1B:B0:C7:D8:5A:A7:F1:02:F5:4A:42:70:02:F1:D5:A4:69:61:86:FF:74:E5:DA:C1:29:D7:E9:2A:B7:A3:F0:2E:20:13:69:A6:14:A6:3E:26:3E:57:2C:B3:CD:14:16:E2:FD:8A:98:4C:40:FB:98:9B:E6:C0:3C:F6:7F:CE:15:B9:48:25:73:D5:98:8A:A8:AB:D2:20:E0:C0:90:97:5C:E7:9F:4D:F1:5F:11:3B:B6:22:68:D7:6E:7D:9E:FB:27:F9:D2:BD:E3:93:AC:8C:93:83:24");

	// 2 Keys, 521 bit EC and 2048 bit RSA
	file = AUTOFILE(JWK_RSA_EC)
	list << keys->index(keys->getByName("521 bit EC"));
	export_by_id(50, file, list, keys);
	jwk = jsonFromFile(file);
	QVERIFY(jwk.isObject());
	o = jwk.toObject();
	QJsonArray jkeys = o["keys"].toArray();
	QVERIFY(jkeys.size() == 2);
	o = jkeys[0].toObject();
	QCOMPARE(o["kty"].toString(), "RSA");
	QCOMPARE(o["kid"].toString(), "2048 bit RSA");
	QCOMPARE(urldecode(o["n"]), "00:A6:83:93:C4:A8:8A:56:77:1C:E4:62:F4:C9:F8:A7:78:85:3B:8D:E8:7D:A6:CB:17:AF:17:59:D9:EB:82:DB:81:64:E0:E6:2C:05:E2:9C:49:6D:EB:67:9D:19:FA:3D:EB:2C:E1:49:07:41:DC:71:B6:ED:70:D1:C7:18:3E:A1:1F:57:52:55:3F:EC:1E:C1:8D:E4:C9:E4:B5:11:D3:74:12:43:6D:15:0B:CC:8A:7C:3D:BC:79:37:41:B8:3B:43:CD:61:61:72:26:D7:A8:8E:B6:F9:D0:5F:C6:F4:E2:C4:6D:2D:96:45:A8:8D:79:00:12:79:1C:6D:F0:D2:94:58:FE:E8:2E:7A:4F:9F:87:37:DA:C0:A1:FB:03:A5:57:02:59:8D:96:EF:57:2B:78:EE:53:6F:93:37:7A:4E:FD:6F:06:A0:8C:02:3C:CC:93:A7:82:0C:4C:35:15:98:06:27:AD:40:75:36:92:2F:1C:52:EA:3D:20:E7:64:0D:1D:EC:6B:CE:C0:0C:0B:53:90:38:D2:E0:B3:F0:FB:0E:D8:40:31:68:36:67:9B:F3:2D:7A:75:B9:95:B5:53:F4:01:2E:9C:2A:F0:18:69:61:73:20:40:B8:DA:F2:FA:CA:2A:E5:7F:AD:BA:FA:02:1F:54:BC:6E:69:48:79:9F:9D:5C:0F:99");
	QCOMPARE(urldecode(o["e"]), "01:00:01");
	QStringList rsa = o.keys();
	for (QString k : QStringList{ "d", "p", "q", "dp", "dq", "qi" })
		QVERIFY(rsa.contains(k));

	o = jkeys[1].toObject();
	QCOMPARE(o["kty"].toString(), "EC");
	QCOMPARE(o["kid"].toString(), "521 bit EC");
	QCOMPARE(o["crv"].toString(), "P-521");
	QCOMPARE(urldecode(o["x"]),"01:53:3D:93:CC:5A:BA:01:5D:B4:AF:05:CF:1F:58:AA:F9:96:7F:72:71:BD:59:0C:61:EA:0A:73:6B:E1:21:C9:2D:EB:2D:CD:D9:33:AF:AA:17:5D:01:56:D0:DD:2A:2E:F5:F1:65:A2:58:C4:B3:45:0F:B8:9F:27:12:C9:8B:75:C1:30");
	QCOMPARE(urldecode(o["y"]),"01:C1:AD:BC:1F:A2:A2:00:A2:44:40:09:7A:C4:06:31:D0:D1:D6:81:EA:70:EA:6C:38:A4:55:DF:80:0A:8E:A7:35:2D:3C:49:B6:84:35:A3:8D:4B:52:A3:E8:92:05:12:3A:3A:99:AE:0C:86:56:53:DE:DD:D9:40:C2:8F:E9:21:E4:FD");
	QCOMPARE(urldecode(o["d"]),"00:1B:8B:37:1E:26:E2:22:2C:2F:BD:99:19:76:90:D5:BF:70:AF:DD:59:DE:35:9E:D4:93:37:B4:1E:6D:48:F1:31:F5:22:3D:12:0F:EF:DD:EF:40:51:42:17:16:44:8C:D9:AF:71:E6:B5:2D:24:0F:CA:98:7C:CA:38:E4:2F:11:4A:3D");

	// 2 Keys, 521 bit EC and 2048 bit RSA as PUBLIC KEYS
	file = AUTOFILE(JWK_RSA_EC_PUB)
	export_by_id(51, file, list, keys);
	jwk = jsonFromFile(file);
	QVERIFY(jwk.isObject());
	o = jwk.toObject();
	jkeys = o["keys"].toArray();
	QVERIFY(jkeys.size() == 2);
	o = jkeys[0].toObject();
	QCOMPARE(o["kty"].toString(), "RSA");
	QCOMPARE(o["kid"].toString(), "2048 bit RSA");
	QCOMPARE(urldecode(o["n"]), "00:A6:83:93:C4:A8:8A:56:77:1C:E4:62:F4:C9:F8:A7:78:85:3B:8D:E8:7D:A6:CB:17:AF:17:59:D9:EB:82:DB:81:64:E0:E6:2C:05:E2:9C:49:6D:EB:67:9D:19:FA:3D:EB:2C:E1:49:07:41:DC:71:B6:ED:70:D1:C7:18:3E:A1:1F:57:52:55:3F:EC:1E:C1:8D:E4:C9:E4:B5:11:D3:74:12:43:6D:15:0B:CC:8A:7C:3D:BC:79:37:41:B8:3B:43:CD:61:61:72:26:D7:A8:8E:B6:F9:D0:5F:C6:F4:E2:C4:6D:2D:96:45:A8:8D:79:00:12:79:1C:6D:F0:D2:94:58:FE:E8:2E:7A:4F:9F:87:37:DA:C0:A1:FB:03:A5:57:02:59:8D:96:EF:57:2B:78:EE:53:6F:93:37:7A:4E:FD:6F:06:A0:8C:02:3C:CC:93:A7:82:0C:4C:35:15:98:06:27:AD:40:75:36:92:2F:1C:52:EA:3D:20:E7:64:0D:1D:EC:6B:CE:C0:0C:0B:53:90:38:D2:E0:B3:F0:FB:0E:D8:40:31:68:36:67:9B:F3:2D:7A:75:B9:95:B5:53:F4:01:2E:9C:2A:F0:18:69:61:73:20:40:B8:DA:F2:FA:CA:2A:E5:7F:AD:BA:FA:02:1F:54:BC:6E:69:48:79:9F:9D:5C:0F:99");
	QCOMPARE(urldecode(o["e"]), "01:00:01");
	for (QString k : QStringList{ "d", "p", "q", "dp", "dq", "qi" })
		QVERIFY(o[k].isNull());

	o = jkeys[1].toObject();
	QCOMPARE(o["kty"].toString(), "EC");
	QCOMPARE(o["kid"].toString(), "521 bit EC");
	QCOMPARE(o["crv"].toString(), "P-521");
	QCOMPARE(urldecode(o["x"]),"01:53:3D:93:CC:5A:BA:01:5D:B4:AF:05:CF:1F:58:AA:F9:96:7F:72:71:BD:59:0C:61:EA:0A:73:6B:E1:21:C9:2D:EB:2D:CD:D9:33:AF:AA:17:5D:01:56:D0:DD:2A:2E:F5:F1:65:A2:58:C4:B3:45:0F:B8:9F:27:12:C9:8B:75:C1:30");
	QCOMPARE(urldecode(o["y"]),"01:C1:AD:BC:1F:A2:A2:00:A2:44:40:09:7A:C4:06:31:D0:D1:D6:81:EA:70:EA:6C:38:A4:55:DF:80:0A:8E:A7:35:2D:3C:49:B6:84:35:A3:8D:4B:52:A3:E8:92:05:12:3A:3A:99:AE:0C:86:56:53:DE:DD:D9:40:C2:8F:E9:21:E4:FD");
	QVERIFY(o["d"].isNull());

	// Import ED25519 Key
	key = new pki_evp();
	key->fromPEMbyteArray(pemdata["ED25519 Key"].toUtf8(), QString("ED25519 Key"));
	openssl_error();
	Database.insert(key);
	dbstatus();

	list.clear();
	key = dynamic_cast<pki_key*>(keys->getByName("ED25519 Key"));
	list << keys->index(key);

	// Export ED25519 as Private SSH Key
	file = AUTOFILE(ED25519PRIVSSH)
	export_by_id(22, file, list, keys);
	verify_key(file, QList<unsigned> { ED25519_HASH }, true);
	check_pems(file, 1, QStringList{ "BEGIN OPENSSH PRIVATE KEY" });

	// Export ED25519 as unencrypted PEM Private Key
	file = AUTOFILE(ED25519PRIVPEM)
	export_by_id(20, file, list, keys);
	verify_key(file, QList<unsigned> { ED25519_HASH }, true);
	check_pems(file, 1, QStringList{ "BEGIN PRIVATE KEY" });

	// Export ED25519 as unencrypted PKCS#8 Key (Same output as above)
	file = AUTOFILE(ED25519PRIVPKCS8)
	export_by_id(29, file, list, keys);
	verify_key(file, QList<unsigned> { ED25519_HASH }, true);
	check_pems(file, 1, QStringList{ "BEGIN PRIVATE KEY" });

	// Export ED25519 as encrypted PKCS#8 Key
	file = AUTOFILE(ED25519PRIVPKCS8ENC)
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("pass", pw_ok),
		new pw_expect("pass", pw_ok),
	});
	export_by_id(28, file, list, keys);
	verify_key(file, QList<unsigned> { ED25519_HASH }, true);
	check_pems(file, 1, QStringList{ "BEGIN ENCRYPTED PRIVATE KEY" });

	// Export XCA Template and verify the internal name and comment
	file = AUTOFILE(XCA_TEMPLATE)
	db_base *temps = Database.model<db_temp>();
	list.clear();
	pki_base *temp = temps->getByName("CA Template"); // The common name
	Q_ASSERT(temp != nullptr);
	Q_ASSERT(temp->getComment().isEmpty());
	temp->setComment("My XCA TEMPLATE comment");
	temp->setIntName("My Template Internal Name");
	list << temps->index(temp);
	export_by_id(35, file, list, temps);
	verify_template(file);
	check_pems(file, 1, QStringList{ "BEGIN XCA TEMPLATE" });

	} catch (...) {
		QString m = QString("Exception thrown L %1").arg(l);
		QVERIFY2(false, m.toUtf8().constData());
	}
}
