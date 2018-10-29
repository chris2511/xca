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
	QStringList schemas[6];

#include "database_schema.cpp"

	XSqlQuery q;
	QSqlDatabase db = QSqlDatabase::database();
	QStringList tables;
	unsigned int i;
	if (!db.isOpen())
		return QSqlError();

	Transaction;
	if (!TransBegin())
		return db.lastError();

	for (i = XSqlQuery::schemaVersion(); i < ARRAY_SIZE(schemas); i++) {
		foreach(QString sql, schemas[i]) {
			qDebug("EXEC[%d]: '%s'", i, CCHAR(sql));
			if (!q.exec(sql) || q.lastError().isValid()) {
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
		close_database();
		opendb->openDatabase();
		QSqlError e = initSqlDB();
		if (e.isValid()) {
			dbSqlError(e);
			QSqlDatabase::database().close();
			dbName = QString();
		} else {
			dbName = opendb->getDescriptor();
		}
		qDebug() << "DB-DESC:" << opendb->getDescriptor() << dbName << e;
	}
	delete opendb;
	return dbName;
}

void MainWindow::openRemoteSqlDB()
{
	init_database("");
}

void MainWindow::set_geometry(QString geo)
{
	QStringList sl = geo.split(",");
	if (sl.size() != 3)
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
	    smartCard << asym_key << tmpl << x509 << x509_req << revocation;

	Settings["pwhash"] = pki_evp::passHash;
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
				pki->pkiSource = legacy_db;
			}
			catch (errorEx &err) {
				err.appendString(pki->getIntName());
				Error(err);
				delete pki;
				pki = NULL;
			}
			free(p);
			if (pki) {
				pki_x509req *r=dynamic_cast<pki_x509req*>(pki);
				if (r && r->issuedCerts() > 0)
					r->setDone();
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
			Settings[set] = val;
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

	if (checkForOldDbFormat(dbName)) {
		QString newname = dbName;
		if (newname.endsWith(".xdb"))
			newname = newname.left(newname.length() -4);
		newname += "_backup_" + QDateTime::currentDateTime()
				.toString("yyyyMMdd_hhmmss") + ".xdb";
		if (!XCA_OKCANCEL(tr("Legacy database format detected. Creating a backup copy called: '%1' and converting the database to the new format").arg(newname))) {
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
	if (!QSqlDatabase::database().isOpen() || dbName.isEmpty()) {
		/* Error already printed */
		return 1;
	}
	certView->setRootIsDecorated(db_x509::treeview);
	ret = 1;
	try {
		if (pki_evp::passwd.isEmpty() && oldDbFile.isEmpty()) {
			ret = initPass(dbName);
			if (ret == 2)
				return ret;
			ret = 0;
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

	if (!oldDbFile.isEmpty())
		importOldDatabase(oldDbFile);

	searchEdit->setText("");
	searchEdit->show();
	statusBar()->addWidget(searchEdit, 1);

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

	set_geometry(Settings["mw_geometry"]);
	setWindowTitle(XCA_TITLE);
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
	QString dirname = QFileDialog::getExistingDirectory(
				this, XCA_TITLE, Settings["workingdir"]);

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

static QString defaultdb()
{
	return getUserSettingsDir() +QDir::separator() + "defaultdb";
}

int MainWindow::open_default_db()
{
	if (QSqlDatabase::database().isOpen())
		return 0;
	QFile inputFile(defaultdb());
	if (!inputFile.open(QIODevice::ReadOnly))
		return 0;
	QTextStream in(&inputFile);
	QString dbfile = in.readLine();
	inputFile.close();

	if (QFile::exists(dbfile) || OpenDb::isRemoteDB(dbfile))
		return init_database(dbfile);
	return 0;
}

void MainWindow::default_database()
{
	if (portable_app())
		return;

	QFile file(defaultdb());
	QFileInfo fi(currentDB);

	if (currentDB.isEmpty()) {
		file.remove();
		return;
	}

	if (file.open(QIODevice::ReadWrite)) {
		QByteArray ba;
		if (OpenDb::isRemoteDB(currentDB))
			ba = filename2bytearray(currentDB);
		else
			ba = filename2bytearray(fi.canonicalFilePath());
		ba += '\n';
		file.write(ba);
		/* write() failed? Harmless. Only inconvenient */
	}
	file.close();
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
		Settings.clear();
		return;
	}
	qDebug("Closing database: %s", QString2filename(currentDB));
	Settings["mw_geometry"] = QString("%1,%2,%3")
			.arg(size().width())
			.arg(size().height())
			.arg(tabView->currentIndex());

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
	crls = NULL;

	QSqlDatabase::database().close();
	pki_evp::passwd.cleanse();
	pki_evp::passwd = QByteArray();


	update_history(currentDB);
	pkcs11::remove_libs();
	enableTokenMenu(pkcs11::loaded());
	QSqlDatabase::removeDatabase(connName);
	currentDB.clear();
	Settings.clear();
	XSqlQuery::clearTablePrefix();
}

static QString dbhistory()
{
	return getUserSettingsDir() + QDir::separator() + "dbhistory";
}

void MainWindow::load_history()
{
	QString name;
	QFile file(dbhistory());
	if (!file.open(QIODevice::ReadOnly))
		return;

	history.clear();
	while (!file.atEnd()) {
		char buf[1024];
		ssize_t size = file.readLine(buf, sizeof buf);
		if (size <= 0)
			break;
		name = filename2QString(buf).trimmed();
		if (name.size() == 0)
			continue;
		if (history.indexOf(name) == -1)
			history << name;
	}
	file.close();
	update_history_menu();
	foreach(name, history) {
		if (OpenDb::isRemoteDB(name)) {
			OpenDb::setLastRemote(name);
			break;
		}
	}
}

void MainWindow::update_history(QString fname)
{
	QFile file;
	int pos;

	pos = history.indexOf(fname);
	if (pos == 0)
		return; /* no changes */

	if (pos > 0)
		history.removeAt(pos);
	history.prepend(fname);
	while (history.size() > 10)
		history.removeLast();

	update_history_menu();

	if (portable_app())
		return;

	file.setFileName(dbhistory());
	if (!file.open(QIODevice::ReadWrite))
		return;

	for (pos = 0; pos < history.size(); pos++) {
		QByteArray ba = filename2bytearray(history[pos]);
		ba.append('\n');
		if (file.write(ba) <= 0)
			break;
	}
	file.close();
}
