/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "lib/exception.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/entropy.h"
#include <QDir>
#include <QDebug>
#include <QStatusBar>
#include <QMessageBox>
#include <QtSql>
#include "lib/db_base.h"
#include "lib/func.h"
#include "lib/db.h"
#include "ImportMulti.h"
#include "NewKey.h"
#include "OpenDb.h"

QSqlError MainWindow::initSqlDB()
{
	QStringList schemas[4]; schemas[0]

/* The "32bit hash" in public_keys, x509super, requests, certs and crls
 * is used to quickly find items in the DB by reference.
 * It consists of the first 4 bytes of a SHA1 hash.
 * Collisions are of course possible.
 *
 * All binaries are stored Base64 encoded in a column of type
 * " B64_BLOB " It is defined here as "VARCHAR(10000)"
 */

#define B64_BLOB "VARCHAR(10000)"

/*
 * The B64(DER(something)) function means DER encode something
 * and then Base64 encode that.
 * So finally this is PEM without newlines, header and footer
 *
 * Dates are alway stored as 'CHAR(15)' in the
 * ASN.1 Generalized time 'yyyyMMddHHmmssZ' format
 */

#define DB_DATE "CHAR(15)"

/*
 * Configuration settings from
 *  the Options dialog, window size, last export directory,
 *  default key type and size,
 *  table column (position, sort order, visibility)
 */
<< "CREATE TABLE settings ("
	"key_ CHAR(20) UNIQUE, " /* mySql does not like "key" or "option" */
	"value VARCHAR(1024))"
<< "INSERT INTO settings (key_, value) VALUES ('schema', '1')"

/*
 * All items (keys, tokens, requests, certs, crls, templates)
 * are stored here with the primary key and some common data
 * The other tables containing the details reference the "id"
 * as FOREIGN KEY.
 */
<< "CREATE TABLE items("
	"id INTEGER PRIMARY KEY, "
	"name VARCHAR(128), "	/* Internal name of the item */
	"type INTEGER, "	/* enum pki_type */
	"source INTEGER, "	/* enum pki_source */
	"date " DB_DATE ", "	/* Time of insertion (creation/import) */
	"comment VARCHAR(2048))"

/*
 * Storage of public keys. Private keys and tokens also store
 * their public part here.
 */
<< "CREATE TABLE public_keys ("
	"item INTEGER, "	/* reference to items(id) */
	"type CHAR(4), "	/* RSA DSA EC (as text) */
	"hash INTEGER, "	/* 32 bit hash */
	"len INTEGER, "		/* key size in bits */
	"public " B64_BLOB ", "	/* B64(DER(public key)) */
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * The private part of RSA, DSA, EC keys.
 * references to "items" and "public_keys"
 */
<< "CREATE TABLE private_keys ("
	"item INTEGER, "	/* reference to items(id) */
	"ownPass INTEGER, "	/* Encrypted by DB pwd or own pwd */
	"private " B64_BLOB ", "	/* B64(Encrypt(DER(private key))) */
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * Smart cards or other PKCS#11 tokens
 * references to "items" and "public_keys"
 */
<< "CREATE TABLE tokens ("
	"item INTEGER, "	/* reference to items(id) */
	"card_manufacturer VARCHAR(64), " /* Card location data */
	"card_serial VARCHAR(64), "	  /* as text */
	"card_model VARCHAR(64), "
	"card_label VARCHAR(64), "
	"slot_label VARCHAR(64), "
	"object_id VARCHAR(64), "	  /* Unique ID on the token */
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * Encryption and hash mechanisms supported by a token
 */
<< "CREATE TABLE token_mechanism ("
	"item INTEGER, "	/* reference to items(id) */
	"mechanism INTEGER, "	/* PKCS#11: CK_MECHANISM_TYPE */
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * An X509 Super class, consisting of a
 *  - Distinguishd name hash
 *  - Referenced key in the database
 *  - hash of the public key, used for lookups if there
 *    is no key to reference
 * used by Requests and certificates and the use-counter of keys:
 * "SELECT from x509super WHERE pkey=?"
 */
<< "CREATE TABLE x509super ("
	"item INTEGER, "	/* reference to items(id) */
	"subj_hash INTEGER, "	/* 32 bit hash of the Distinguished name */
	"pkey INTEGER, "	/* reference to the key items(id) */
	"key_hash INTEGER, "	/* 32 bit hash of the public key */
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (pkey) REFERENCES items (id)) "

/*
 * PKCS#10 Certificate request details
 * also takes information from the "x509super" table.
 */
<< "CREATE TABLE requests ("
	"item INTEGER, "	/* reference to items(id) */
	"hash INTEGER, "	/* 32 bit hash of the request */
	"signed INTEGER, "	/* Whether it was once signed. */
	"request " B64_BLOB ", "	/* B64(DER(PKCS#10 request)) */
	"FOREIGN KEY (item) REFERENCES items (id)) "

/*
 * X509 certificate details
 * also takes information from the "x509super" table.
 * The content of the columns: hash, iss_hash, serial, ca
 * can also be retrieved directly from the certificate, but are good
 * to lurk around for faster lookup
 */
<< "CREATE TABLE certs ("
	"item INTEGER, "	/* reference to items(id) */
	"hash INTEGER, "	/* 32 bit hash of the cert */
	"iss_hash INTEGER, "	/* 32 bit hash of the issuer DN */
	"serial VARCHAR(64), "	/* Serial number of the certificate */
	"issuer INTEGER, "	/* The items(id) of the issuer or NULL */
	"ca INTEGER, "		/* CA: yes / no from BasicConstraints */
	"cert " B64_BLOB ", "	/* B64(DER(certificate)) */
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (issuer) REFERENCES items (id)) "

/*
 * X509 cartificate Authority data
 */
<< "CREATE TABLE authority ("
	"item INTEGER, "	/* reference to items(id) */
	"template INTEGER, "	/* reference to items(id) of the default template*/
	"crlExpire " DB_DATE ", "	/* CRL expiry date */
	"crlNo INTEGER, "	/* Last CRL Number */
	"crlDays INTEGER, "	/* CRL days until renewal */
	"dnPolicy VARCHAR(1024), "	/* DistinguishedName policy */
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (template) REFERENCES items (id)) "

/*
 * Storage of CRLs
 */
<< "CREATE TABLE crls ("
	"item INTEGER, "	/* reference to items(id) */
	"hash INTEGER, "	/* 32 bit hash of the CRL */
	"num INTEGER, "		/* Number of revoked certificates */
	"iss_hash INTEGER, "	/* 32 bit hash of the issuer DN */
	"issuer INTEGER, "	/* The items(id) of the issuer or NULL */
	"crl " B64_BLOB ", "	/* B64(DER(revocation list)) */
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (issuer) REFERENCES items (id)) "

/*
 * Revocations (serial, date, reason, issuer) used to create new
 * CRLs. "Manage revocations"
 */
<< "CREATE TABLE revocations ("
	"caId INTEGER, "        /* reference to certs(item) */
	"serial VARCHAR(64), "	/* Serial number of the revoked certificate */
	"date " DB_DATE ", "	/* Time of creating the revocation */
	"invaldate " DB_DATE ", "	/* Time of invalidation */
	"crlNo INTEGER, "	/* Crl Number of CRL of first appearance */
	"reasonBit INTEGER, "	/* Bit number of the revocation reason */
	"FOREIGN KEY (caId) REFERENCES items (id))"

/*
 * Templates
 */
<< "CREATE TABLE templates ("
	"item INTEGER, "        /* reference to items(id) */
	"version INTEGER, "	/* Version of the template format */
	"template " B64_BLOB ", "	/* The base64 encoded template */
	"FOREIGN KEY (item) REFERENCES items (id))"

	;
/* Schema Version 2: Views added to quickly load the data */
	schemas[1]

/* Views */
<< "CREATE VIEW view_public_keys AS SELECT "
	"items.id, items.name, items.type AS item_type, items.date, "
	"items.source, items.comment, "
	"public_keys.type as key_type, public_keys.len, public_keys.public, "
	"private_keys.ownPass, "
	"tokens.card_manufacturer, tokens.card_serial, tokens.card_model, "
	"tokens.card_label, tokens.slot_label, tokens.object_id "
	"FROM public_keys LEFT JOIN items ON public_keys.item = items.id "
	"LEFT JOIN private_keys ON private_keys.item = public_keys.item "
	"LEFT JOIN tokens ON public_keys.item = tokens.item"

<< "CREATE VIEW view_certs AS SELECT "
	"items.id, items.name, items.type, items.date AS item_date, "
	"items.source, items.comment, "
	"x509super.pkey, "
	"certs.serial AS certs_serial, certs.issuer, certs.ca, certs.cert, "
	"authority.template, authority.crlExpire, "
	"authority.crlNo AS auth_crlno, authority.crlDays, authority.dnPolicy, "
	"revocations.serial, revocations.date, revocations.invaldate, "
	"revocations.crlNo, revocations.reasonBit "
	"FROM certs LEFT JOIN items ON certs.item = items.id "
	"LEFT JOIN x509super ON x509super.item = certs.item "
	"LEFT JOIN authority ON authority.item = certs.item "
	"LEFT JOIN revocations ON revocations.caId = certs.issuer "
				"AND revocations.serial = certs.serial"

<< "CREATE VIEW view_requests AS SELECT "
	"items.id, items.name, items.type, items.date, "
	"items.source, items.comment, "
	"x509super.pkey, "
	"requests.request, requests.signed "
	"FROM requests LEFT JOIN items ON requests.item = items.id "
	"LEFT JOIN x509super ON x509super.item = requests.item"

<< "CREATE VIEW view_crls AS SELECT "
	"items.id, items.name, items.type, items.date, "
	"items.source, items.comment, "
	"crls.num, crls.issuer, crls.crl "
	"FROM crls LEFT JOIN items ON crls.item = items.id "

<< "CREATE VIEW view_templates AS SELECT "
	"items.id, items.name, items.type, items.date, "
	"items.source, items.comment, "
	"templates.version, templates.template "
	"FROM templates LEFT JOIN items ON templates.item = items.id"


<< "UPDATE settings SET value='2' WHERE key_='schema'"

	;
/* Schema Version 3: Add indexes over hashes and primary, foreign keys */
	schemas[2]

<< "CREATE INDEX i_settings_key_ ON settings (key_)"
<< "CREATE INDEX i_items_id ON items (id)"
<< "CREATE INDEX i_public_keys_item ON public_keys (item)"
<< "CREATE INDEX i_public_keys_hash ON public_keys (hash)"
<< "CREATE INDEX i_private_keys_item ON private_keys (item)"
<< "CREATE INDEX i_tokens_item ON tokens (item)"
<< "CREATE INDEX i_token_mechanism_item ON token_mechanism (item)"
<< "CREATE INDEX i_x509super_item ON x509super (item)"
<< "CREATE INDEX i_x509super_subj_hash ON x509super (subj_hash)"
<< "CREATE INDEX i_x509super_key_hash ON x509super (key_hash)"
<< "CREATE INDEX i_x509super_pkey ON x509super (pkey)"
<< "CREATE INDEX i_requests_item ON requests (item)"
<< "CREATE INDEX i_requests_hash ON requests (hash)"
<< "CREATE INDEX i_certs_item ON certs (item)"
<< "CREATE INDEX i_certs_hash ON certs (hash)"
<< "CREATE INDEX i_certs_iss_hash ON certs (iss_hash)"
<< "CREATE INDEX i_certs_serial ON certs (serial)"
<< "CREATE INDEX i_certs_issuer ON certs (issuer)"
<< "CREATE INDEX i_certs_ca ON certs (ca)"
<< "CREATE INDEX i_authority_item ON authority (item)"
<< "CREATE INDEX i_crls_item ON crls (item)"
<< "CREATE INDEX i_crls_hash ON crls (hash)"
<< "CREATE INDEX i_crls_iss_hash ON crls (iss_hash)"
<< "CREATE INDEX i_crls_issuer ON crls (issuer)"
<< "CREATE INDEX i_revocations_caId_serial ON revocations (caId, serial)"
<< "CREATE INDEX i_templates_item ON templates (item)"
<< "UPDATE settings SET value='3' WHERE key_='schema'"

	;
/* Schema Version 4: Add private key view to extract a private key with:
	mysql:      mysql -sNp -u xca xca_msq -e
	or sqlite:  sqlite3 ~/sqlxdb.xdb
	or psql:    psql -t -h 192.168.140.7 -U xca -d xca_pg -c
		"SELECT private FROM view_private WHERE name='pk8key';" |\
		base64 -d | openssl pkcs8 -inform DER
 * First mysql/psql will ask for a password and then OpenSSL will ask for
 * the database password.
 */
	schemas[3]

<< "CREATE VIEW view_private AS SELECT "
	"name, private FROM private_keys JOIN items ON "
	"items.id = private_keys.item"
<< "UPDATE settings SET value='4' WHERE key_='schema'"
	;

	XSqlQuery q;
	QSqlDatabase db = QSqlDatabase::database();
	QStringList tables;
	unsigned i = 0;

	if (!db.isOpen())
		return QSqlError();

	tables = db.tables();

	if (tables.contains("settings")) {
		QString schema = getSetting("schema");
		i = schema.toInt();
	}
	Transaction;
	if (!TransBegin())
		return db.lastError();

	for (; i < ARRAY_SIZE(schemas); i++) {
		foreach(QString sql, schemas[i]) {
			qDebug("EXEC[%d]: '%s'", i, CCHAR(sql));
			if (!q.exec(sql)) {
				TransRollback();
				return q.lastError();
			}
		}
	}
	TransCommit();
	return QSqlError();
}

QString MainWindow::openSqlDB(QString dbName)
{
	OpenDb *opendb = new OpenDb(this, dbName);
	if (opendb->exec()) {
		opendb->openDatabase();
		QSqlError e = initSqlDB();
		qDebug() << "DB-DESC:" << opendb->getDescriptor();
		if (e.isValid()) {
			dbSqlError();
			dbName = QString();
		} else {
			dbName = opendb->getDescriptor();
		}
	}
	delete opendb;
	return dbName;
}

void MainWindow::openRemoteSqlDB()
{
	close_database();
	init_database("@/QPSQL7:");
}

void MainWindow::set_geometry(QString geo)
{
	QStringList sl = geo.split(",");
	if (sl.size() != 2)
		return;
	resize(sl[0].toInt(), sl[1].toInt());
	int i = sl[2].toInt();
	if (i != -1)
		tabView->setCurrentIndex(i);
}

void MainWindow::dbSqlError(QSqlError err)
{
	if (!err.isValid())
		err = QSqlDatabase::database().lastError();

	if (err.isValid()) {
		qCritical() << "SQL ERROR:" << err.text();
		XCA_WARN(err.text());
	}
}

bool MainWindow::checkForOldDbFormat(QString dbfile)
{
	// 0x ca db 19 69
	static const unsigned char magic[] = { 0xca, 0xdb, 0x19, 0x69 };
	char head[4];

	QFile file(dbfile);
	if (!file.open(QIODevice::ReadOnly))
		return 0;
	file.read(head, sizeof head);
	file.close();
	return !memcmp(head, magic, sizeof head);
}

int MainWindow::verifyOldDbPass(QString dbname)
{
	// look for the password
	QString passhash;
	db_header_t head;
	class db mydb(dbname);
	mydb.first();
	if (!mydb.find(setting, QString("pwhash"))) {
		QString val;
		char *p;
		if ((p = (char *)mydb.load(&head))) {
			passhash = p;
			free(p);
			return initPass(dbname, passhash);
		}
	}
	return 2;
}

void MainWindow::importOldDatabase(QString dbname)
{
	class db mydb(dbname);
	unsigned char *p = NULL;
	db_header_t head;
	pki_base *pki;
	db_base *cont;
	QList<enum pki_type> pkitype; pkitype <<
	    smartCard << asym_key << tmpl << x509_req << x509 << revocation;

	storeSetting("pwhash", pki_evp::passHash);
	for (int i=0; i < pkitype.count(); i++) {
		mydb.first();
		while (mydb.find(pkitype[i], QString()) == 0) {
			QString s;
			p = mydb.load(&head);
			if (!p) {
				qWarning("Load was empty !");
				goto next;
			}
			switch (pkitype[i]) {
			case smartCard:
				cont = keys;
				pki = new pki_scard("");
				break;
			case asym_key:
				cont = keys;
				pki = new pki_evp();
				break;
			case x509_req:
				cont = reqs;
				pki = new pki_x509req();
				break;
			case x509:
				cont = certs;
				pki = new pki_x509();
				break;
			case revocation:
				cont = crls;
				pki = new pki_crl();
				break;
			case tmpl:
				cont = temps;
				pki = new pki_temp();
				break;
			default:
				goto next;
			}
			pki->setIntName(QString::fromUtf8(head.name));

			try {
				pki->fromData(p, &head);
			}
			catch (errorEx &err) {
				err.appendString(pki->getIntName());
				Error(err);
				delete pki;
				pki = NULL;
			}
			free(p);
			if (pki) {
				qDebug() << "load old:" << pki->getIntName();
				cont->insertPKI(pki);
			}
next:
			if (mydb.next())
				break;
		}
	}
	QStringList sl; sl << "workingdir" << "pkcs11path" <<
		"default_hash" << "mandatory_dn" << "explicit_dn" <<
		"string_opt" << "optionflags1" << "defaultkey";

	mydb.first();
	while (!mydb.find(setting, QString())) {
		QString val;
		char *p;
		if ((p = (char *)mydb.load(&head))) {
			val = p;
			free(p);
		}
		QString set = QString::fromUtf8(head.name);
		if (sl.contains(set)) {
			if (set == "optionflags1")
				set = "optionflags";
			storeSetting(set, val);
		}
		if (mydb.next())
			break;
	}
}

int MainWindow::init_database(QString dbName)
{
	int ret = 2;
	QSqlError err;
	QString oldDbFile;

	qDebug("Opening database: %s", QString2filename(dbName));
	keys = NULL; reqs = NULL; certs = NULL; temps = NULL; crls = NULL;

	if (checkForOldDbFormat(dbName)) {
		QString newname = dbName;
		if (newname.endsWith(".xdb"))
			newname = newname.left(newname.length() -4);
		newname += "_backup_" + QDateTime::currentDateTime()
				.toString("yyyyMMdd_hhmmss") + ".xdb";
		if (!XCA_OKCANCEL(tr("Found an old version of the XCA database. I will make a backup copy called: '%1' and convert the database into the new format").arg(newname))) {
			return 1;
		}
		if (verifyOldDbPass(dbName) != 1)
			return 1;
		if (!QFile::rename(dbName, newname)) {
			XCA_WARN(tr("Failed to rename the database file, because the target already exists"));
			return 1;
		}
		oldDbFile = newname;
	}
	Entropy::seed_rng();
	dbName = openSqlDB(dbName);
	if (!QSqlDatabase::database().isOpen()) {
		/* Error already printed */
		return 1;
	}
	certView->setRootIsDecorated(db_x509::treeview);

	try {
		if (pki_evp::passwd.isEmpty()) {
			ret = initPass(dbName);
			if (ret == 2)
				return ret;
		}
		keys = new db_key(this);
		reqs = new db_x509req(this);
		certs = new db_x509(this);
		temps = new db_temp(this);
		crls = new db_crl(this);
	}
	catch (errorEx &err) {
		Error(err);
		return ret;
	}

	searchEdit->setText("");
	searchEdit->show();
	statusBar()->addWidget(searchEdit, 1);
	mandatory_dn = "";
	explicit_dn = explicit_dn_default;

	string_opt = QString("MASK:0x2002");
	ASN1_STRING_set_default_mask_asc((char*)CCHAR(string_opt));
	hashBox::resetDefault();
	pkcs11path = QString();
	workingdir = QDir::currentPath();
	setOptFlags((QString()));

	connect( certs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );
	connect( reqs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );

	connect( reqs, SIGNAL(newCert(pki_x509req *)),
		certs, SLOT(newCert(pki_x509req *)) );
	connect( tempView, SIGNAL(newCert(pki_temp *)),
		certs, SLOT(newCert(pki_temp *)) );
	connect( tempView, SIGNAL(newReq(pki_temp *)),
		reqs, SLOT(newItem(pki_temp *)) );

	keyView->setIconSize(pki_evp::icon[0]->size());
	reqView->setIconSize(pki_x509req::icon[0]->size());
	certView->setIconSize(pki_x509::icon[0]->size());
	tempView->setIconSize(pki_temp::icon->size());
	crlView->setIconSize(pki_crl::icon->size());

	keyView->setModel(keys);
	reqView->setModel(reqs);
	certView->setModel(certs);
	tempView->setModel(temps);
	crlView->setModel(crls);

	if (!oldDbFile.isEmpty())
		importOldDatabase(oldDbFile);

	XSqlQuery query("SELECT key_, value FROM settings");
	while (query.next()) {
		QString key = query.value(0).toString();
		QString value = query.value(1).toString();
		if (key == "workingdir")
			workingdir = value;
		else if (key == "pkcs11path")
			pkcs11path = value;
		else if (key == "default_hash")
			hashBox::setDefault(value);
		else if (key == "mandatory_dn")
			mandatory_dn = value;
		else if (key == "explicit_dn")
			explicit_dn = value;
		else if (key == "string_opt")
			string_opt = value;
		else if (key == "optionflags")
			setOptFlags(value);
		else if (key == "defaultkey")
			NewKey::setDefault(value);
		else if (key == "mw_geometry")
			set_geometry(value);
	}
	ASN1_STRING_set_default_mask_asc((char*)CCHAR(string_opt));
	if (explicit_dn.isEmpty())
		explicit_dn = explicit_dn_default;
	setWindowTitle(tr(XCA_TITLE));
	setItemEnabled(true);
	if (pki_evp::passwd.isNull())
		XCA_INFO(tr("Using or exporting private keys will not be possible without providing the correct password"));

	load_engine();
	hashBox hb(this);
	if (hb.isInsecure()) {
		XCA_WARN(tr("The currently used default hash '%1' is insecure. Please select at least 'SHA 224' for security reasons.").arg(hb.currentHashName()));
		setOptions();
	}
	dbindex->setText(tr("Database") + ": " + dbName);
	currentDB = dbName;
	return ret;
}

void MainWindow::dump_database()
{
	QString dirname = QFileDialog::getExistingDirectory(this, tr(XCA_TITLE),
			getPath());

	if (dirname.isEmpty())
		return;

	QDir d(dirname);
	if ( ! d.exists() && !d.mkdir(dirname)) {
		errorEx err("Could not create '" + dirname + "'");
		MainWindow::Error(err);
		return;
	}

	qDebug() << "Dumping to" << dirname;
	try {
		keys->dump(dirname);
		certs->dump(dirname);
		temps->dump(dirname);
		crls->dump(dirname);
		reqs->dump(dirname);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
}

void MainWindow::undelete()
{
#warning undelete NOT WORKING!
	qDebug("undelete NOT WORKING!");
#if 0
	ImportMulti *dlgi = new ImportMulti(this);
	db_header_t head;
	db mydb(dbfile);

	for (mydb.first(DBFLAG_OUTDATED); !mydb.eof(); mydb.next(DBFLAG_OUTDATED)) {
		mydb.get_header(&head);
		if (head.flags & DBFLAG_DELETED) {
			pki_base *item;
			unsigned char *p = NULL;
			QString name = QString::fromUtf8(head.name);
			switch (head.type) {
			case asym_key: item = new pki_evp(name); break;
			case x509_req: item = new pki_x509req(name); break;
			case x509: item = new pki_x509(name); break;
			case revocation: item = new pki_crl(name); break;
			case tmpl: item = new pki_temp(name); break;
			case smartCard: item = new pki_scard(name); break;
			default: continue;
			}
			try {
				p = mydb.load(&head);
				item->fromData(p, &head);
				dlgi->addItem(item);
			}
			catch (errorEx &err) {
				Error(err);
				delete item;
			}
			free(p);
		}
	}
	if (dlgi->entries() > 0) {
		dlgi->execute(1);
	} else {
		XCA_INFO(tr("No deleted items found"));
	}
	delete dlgi;
#endif
}

int MainWindow::open_default_db()
{
	if (QSqlDatabase::database().isOpen())
		return 0;
	FILE *fp = fopen_read(getUserSettingsDir() +
			QDir::separator() + "defaultdb");
	if (!fp)
		return 0;

	char buff[256];
	size_t len = fread(buff, 1, 255, fp);
	fclose(fp);
	buff[len] = 0;
	QString dbfile = filename2QString(buff).trimmed();
	if (QFile::exists(dbfile))
		return init_database(dbfile);
	return 0;
}

void MainWindow::default_database()
{
	QFileInfo fi(currentDB);
	QString dir = getUserSettingsDir();
	QString file = dir +QDir::separator() +"defaultdb";
	FILE *fp;
	QDir d;

	if (currentDB.isEmpty()) {
		QFile::remove(file);
		return;
	}
	d.mkpath(dir);

	fp = fopen_write(file);
	if (fp) {
		QByteArray ba;
		ba = filename2bytearray(fi.canonicalFilePath() + "\n");
		if (fwrite(ba.constData(), ba.size(), 1, fp)) {
			/* IGNORE_RESULT */
		}
		fclose(fp);
	}

}

QString MainWindow::getSetting(QString key)
{
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT value FROM settings WHERE key_=?");
	q.bindValue(0, key);
	q.exec();
	if (q.first()) {
		return q.value(0).toString();
	}
	dbSqlError(q.lastError());
	return QString();
}

void MainWindow::storeSetting(QString key, QString value)
{
	XSqlQuery q;
	QSqlError e;

	SQL_PREPARE(q, "SELECT COUNT(key_) FROM settings WHERE key_=?");
	q.bindValue(0, key);
	q.exec();
	dbSqlError(q.lastError());
	if (q.first() && q.value(0).toInt() == 1)
		SQL_PREPARE(q, "UPDATE settings SET value=? WHERE key_=?");
	else
		SQL_PREPARE(q, "INSERT INTO settings (value, key_) VALUES (?,?)");
	q.bindValue(0, value);
	q.bindValue(1, key);
	q.exec();
	dbSqlError(q.lastError());
}

void MainWindow::close_database()
{
	QByteArray ba;
	QString connName;
	bool dbopen;

	{
		/* Destroy "db" at the end of the block */
		QSqlDatabase db = QSqlDatabase::database();
		connName= db.connectionName();
		dbopen = db.isOpen();
	}

	if (!dbopen) {
		QSqlDatabase::removeDatabase(connName);
		return;
	}
	qDebug("Closing database: %s", QString2filename(currentDB));
	QString s = QString("%1,%2,%3")
		.arg(size().width()).arg(size().height())
		.arg(tabView->currentIndex());
	storeSetting("mw_geometry", s);

	setItemEnabled(false);
	statusBar()->removeWidget(searchEdit);
	dbindex->clear();

	keyView->setModel();
	reqView->setModel();
	certView->setModel();
	tempView->setModel();
	crlView->setModel();

	if (crls)
		delete(crls);
	if (reqs)
		delete(reqs);
	if (certs)
		delete(certs);
	if (temps)
		delete(temps);
	if (keys)
		delete(keys);

	db_base::flushLookup();
	reqs = NULL;
	certs = NULL;
	temps = NULL;
	keys = NULL;

	QSqlDatabase::database().close();
	pki_evp::passwd.cleanse();
	pki_evp::passwd = QByteArray();

	if (!crls)
		return;
	crls = NULL;

	update_history(currentDB);
	pkcs11::remove_libs();
	enableTokenMenu(pkcs11::loaded());
	QSqlDatabase::removeDatabase(connName);
	currentDB.clear();
}

void MainWindow::load_history()
{
	QFile file;
	QString name = getUserSettingsDir() + QDir::separator() + "dbhistory";

	file.setFileName(name);
	if (!file.open(QIODevice::ReadOnly))
		return;

	history.clear();
	while (!file.atEnd()) {
		QString name;
		char buf[1024];
		ssize_t size = file.readLine(buf, sizeof buf);
		if (size <= 0)
			break;
		name = filename2QString(buf);
		name = name.trimmed();
		if (name.size() == 0)
			continue;
		if (history.indexOf(name) == -1)
			history << name;
	}
	file.close();
	update_history_menu();
}

void MainWindow::update_history(QString fname)
{
	QFile file;
	int pos;
	QString name, dir = getUserSettingsDir();
	QDir d;

	pos = history.indexOf(fname);
	if (pos == 0)
		return; /* no changes */

	d.mkpath(dir);

	if (pos > 0)
		history.removeAt(pos);
	history.prepend(fname);
	while (history.size() > 10)
		history.removeLast();

	name = dir + QDir::separator() + "dbhistory";
	file.setFileName(name);
	if (!file.open(QIODevice::ReadWrite))
		return;

	for (pos = 0; pos < history.size(); pos++) {
		QByteArray ba = filename2bytearray(history[pos]);
		ba.append('\n');
		if (file.write(ba) <= 0)
			break;
	}
	file.close();
	update_history_menu();
}
