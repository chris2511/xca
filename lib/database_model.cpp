/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QDir>
#include <QDebug>
#include "widgets/XcaWarning.h"
#include "widgets/OpenDb.h"
#include "widgets/PwDialog.h"

#include "exception.h"
#include "database_model.h"
#include "pki_temp.h"
#include "pki_x509req.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "pki_multi.h"
#include "entropy.h"
#include "db_base.h"
#include "sql.h"
#include "func.h"
#include "db.h"
#include "settings.h"
#include "entropy.h"
#include "pass_info.h"

#include "db_key.h"
#include "db_x509.h"
#include "db_crl.h"
#include "db_x509req.h"
#include "db_temp.h"

xca_db Database;

QSqlError database_model::initSqlDB()
{
#define MAX_SCHEMAS 7
#define SCHEMA_VERSION "7"

	QStringList schemas[MAX_SCHEMAS];

#include "widgets/database_schema.cpp"

	XSqlQuery q;
	QSqlDatabase db = QSqlDatabase::database();
	QStringList tables;
	unsigned int i;

	if (!db.isOpen())
		return QSqlError();

	Transaction;
	if (!TransBegin())
		return db.lastError();

	for (;;) {
		i = XSqlQuery::schemaVersion();
		if (i >= ARRAY_SIZE(schemas))
			break;
		foreach(QString sql, schemas[i]) {
			qDebug("EXEC[%d]: '%s'", i, CCHAR(sql));
			if (!q.exec(sql) || q.lastError().isValid()) {
				TransRollback();
				return q.lastError();
			}
		}
	}

	if (i != MAX_SCHEMAS)
		throw errorEx(tr("Failed to update the database schema to the current version"));

	TransCommit();
	return QSqlError();
}

bool database_model::checkForOldDbFormat(const QString &dbfile) const
{
	// 0x ca db 19 69
	static const unsigned char magic[] = { 0xca, 0xdb, 0x19, 0x69 };
	char head[4];

	XFile file(dbfile);
	if (!file.exists())
		return 0;
	if (!file.open(QIODevice::ReadOnly))
		return 0;
	file.read(head, sizeof head);
	file.close();
	return !memcmp(head, magic, sizeof head);
}

enum open_result database_model::verifyOldDbPass(const QString &dbname) const
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
	return open_abort;
}

QString database_model::checkPre2Xdatabase() const
{
	enum open_result result;
	if (!checkForOldDbFormat(dbName))
		return QString();

	QString newname = dbName;
	if (newname.endsWith(".xdb"))
		newname = newname.left(newname.length() -4);
	newname += "_backup_" + QDateTime::currentDateTime()
			.toString("yyyyMMdd_hhmmss") + ".xdb";
	if (!XCA_OKCANCEL(tr("Legacy database format detected. Creating a backup copy called: '%1' and converting the database to the new format").arg(newname))) {
		throw open_abort;
	}

	result = verifyOldDbPass(dbName);
	if (result != pw_ok)
		throw result;

	if (!QFile::rename(dbName, newname)) {
		XCA_WARN(tr("Failed to rename the database file, because the target already exists"));
		throw open_abort;
	}
	return newname;
}

void database_model::importOldDatabase(const QString &dbname)
{
	class db mydb(dbname);
	unsigned char *p = NULL;
	db_header_t head;
	pki_base *pki;
	db_base *db;
	QList<enum pki_type> pkitype {
		smartCard, asym_key, tmpl, x509, x509_req, revocation
	};

	Settings["pwhash"] = pki_evp::passHash;
	for (int i=0; i < pkitype.count(); i++) {
		mydb.first();
		while (mydb.find(pkitype[i], QString()) == 0) {
			QString s;
			p = mydb.load(&head);
			enum pki_type type = pkitype[i];

			if (!p) {
				qWarning("Load was empty !");
				goto next;
			}
			switch (type) {
			case smartCard:
				db = model<db_key>();
				pki = new pki_scard("");
				break;
			case asym_key:
				db = model<db_key>();
				pki = new pki_evp();
				break;
			case x509_req:
				db = model<db_x509req>();
				pki = new pki_x509req();
				break;
			case x509:
				db = model<db_x509>();
				pki = new pki_x509();
				break;
			case revocation:
				db = model<db_crl>();
				pki = new pki_crl();
				break;
			case tmpl:
				db = model<db_temp>();
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
				delete pki;
				throw err;
			}
			free(p);
			if (pki) {
				pki_x509req *r=dynamic_cast<pki_x509req*>(pki);
				if (r && r->issuedCerts() > 0)
					r->setDone();
				qDebug() << "load old:" << pki->getIntName();
				pki = db->insertPKI(pki);
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

database_model::database_model(const QString &name, const Passwd &pass)
{
	enum open_result result;
	QSqlError err;
	QString oldDbFile;

	dbName = name;
	dbTimer = 0;

	if (dbName.isEmpty())
		dbName = get_default_db();

	if (dbName.isEmpty())
		throw open_abort;

	qDebug() << "Opening database:" << dbName;

	if (!isRemoteDB(dbName))
		oldDbFile = checkPre2Xdatabase();

	Passwd passwd(pass);
	do {
		try {
			openDatabase(dbName, passwd);
			break;
		} catch (errorEx &err) {
			if (!isRemoteDB(dbName))
				throw err;
			if (!passwd.isEmpty())
				XCA_ERROR(err);
			DbMap params = splitRemoteDbName(dbName);
			pass_info p(XCA_TITLE, tr("Please enter the password to access the database server %2 as user '%1'.")
					.arg(params["user"]).arg(params["host"]));
			result = PwDialog::execute(&p, &passwd);
			if (result != pw_ok)
				throw result;
		}
	} while (1);

	Entropy::seed_rng();
	initSqlDB();

	if (oldDbFile.isEmpty()) {
		result = initPass(dbName, Settings["pwhash"]);
		if (result == pw_exit)
			throw pw_exit;
		if (result != pw_ok && Settings["pwhash"].empty())
			throw open_abort;
	}
	/* Assure initialisation order:
	 * keys first, followed by x509[req], and crls last.
	 * Templates don't care.
	 */
	models << new db_key();
	models << new db_x509req();
	models << new db_x509();
	models << new db_crl();
	models << new db_temp();

	foreach(db_base *m, models) {
		check_oom(m);
		connect(m, SIGNAL(pkiChanged(pki_base*)),
			this, SLOT(pkiChangedSlot(pki_base*)));
	}
	if (!oldDbFile.isEmpty())
		importOldDatabase(oldDbFile);

	pkcs11::libraries.load(Settings["pkcs11path"]);
	restart_timer();
}

db_base *database_model::modelForPki(const pki_base *pki) const
{
	if (dynamic_cast<const pki_x509*>(pki))
		return model<db_x509>();
	if (dynamic_cast<const pki_key*>(pki))
		return model<db_key>();
	if (dynamic_cast<const pki_x509req*>(pki))
		return model<db_x509req>();
	if (dynamic_cast<const pki_crl*>(pki))
		return model<db_crl>();
	if (dynamic_cast<const pki_temp*>(pki))
		return model<db_temp>();
	return NULL;
}

pki_base *database_model::insert(pki_base *pki)
{
	db_base *db = modelForPki(pki);
	if (db)
		return db->insert(pki);
	pki_multi *multi = dynamic_cast<pki_multi*>(pki);
	if (multi) {
		QList<pki_base *> items = multi->pull();
		foreach(pki_base *i, items)
			insert(i);
	}
	delete pki;
	return NULL;
}

void database_model::restart_timer()
{
	if (!IS_GUI_APP)
		return;
	killTimer(dbTimer);
	dbTimer = startTimer(1500);
	foreach(db_base *m, models)
		m->restart_timer();
}

void database_model::timerEvent(QTimerEvent *event)
{
	quint64 stamp;
	if (event->timerId() != dbTimer)
		return;
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT MAX(stamp) from items");
	q.exec();
	if (!q.first())
		return;
	stamp = q.value(0).toULongLong();
	q.finish();

	if (stamp > DbTransaction::DatabaseStamp) {
		SQL_PREPARE(q, "SELECT DISTINCT type FROM items WHERE stamp=?");
		q.bindValue(0, stamp);
		q.exec();

		QList<enum pki_type> typelist;
		while (q.next())
			typelist << (enum pki_type)q.value(0).toInt();

		q.finish();
		qDebug() << "CHANGED" << typelist;
		foreach(db_base *model, models)
			model->reloadContainer(typelist);
	}
	DbTransaction::DatabaseStamp = stamp;
}

void database_model::dump_database(const QString &dirname) const
{
	if (dirname.isEmpty())
		return;

	QDir d(dirname);
	if (!d.exists() && !d.mkdir(dirname)) {
		throw errorEx(tr("Unable to create '%1': %2").arg(dirname));
		return;
	}

	qDebug() << "Dumping to" << dirname;
	foreach(db_base *model, models)
		model->dump(dirname);
}

static QString defaultdb()
{
	return getUserSettingsDir() + "/defaultdb";
}

QString database_model::get_default_db() const
{
	if (QSqlDatabase::database().isOpen())
		return QString();

	QFile inputFile(defaultdb());
	if (!inputFile.open(QIODevice::ReadOnly))
		return QString();

	char buf[2048];
	int ret = inputFile.readLine(buf, sizeof buf);
	if (ret < 1)
		return 0;

	inputFile.close();

	QString dbfile = QString::fromUtf8(QByteArray(buf, ret)).trimmed();

	if (QFile::exists(dbfile) || isRemoteDB(dbfile))
		return dbfile;
	return QString();
}

void database_model::as_default_database(const QString &db)
{
	QFile file(defaultdb());

	if (db.isEmpty()) {
		file.remove();
		return;
	}

	if (file.open(QIODevice::ReadWrite | QIODevice::Truncate)) {
		QByteArray ba = isRemoteDB(db) ?
			db.toUtf8() : relativePath(db).toUtf8();
		file.write(ba + '\n');
		/* write() failed? Harmless. Only inconvenient */
	}
	file.close();
}

database_model::~database_model()
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
	killTimer(dbTimer);

	qDeleteAll(models);
	models.clear();
	Store.flush();

	XSqlQuery q("VACUUM");

	QSqlDatabase::database().close();
	pki_evp::passwd.cleanse();

	pkcs11::libraries.remove_libs();
	QSqlDatabase::removeDatabase(connName);
	Settings.clear();
	XSqlQuery::clearTablePrefix();
}

#define NUM_PARAM 6
#define NUM_PARAM_LEAST 5

DbMap database_model::splitRemoteDbName(const QString &db)
{
	static const char * const names[NUM_PARAM] =
		{ "all", "user", "host", "type", "dbname", "prefix" };
	DbMap map;
	QRegExp rx("(.*)@(.*)/(.*):([^#]*)#?([^#]*)");
	int i, pos = rx.indexIn(db);
	QStringList list = rx.capturedTexts();

	if (pos != -1 && list.size() >= NUM_PARAM_LEAST) {
		if (list.size() == NUM_PARAM_LEAST)
			list[NUM_PARAM_LEAST] = "";
		list[NUM_PARAM_LEAST] = list[NUM_PARAM_LEAST].toLower();
		for (i=0; i < NUM_PARAM; i++) {
			map[names[i]] = list[i];
		}
		qDebug() << "SPLIT DB:" << map;
	}
	return map;
}

bool database_model::isRemoteDB(const QString &db)
{
	DbMap remote_param = splitRemoteDbName(db);
	return remote_param.size() == NUM_PARAM;
}

void database_model::openRemoteDatabase(const QString &connName,
				const DbMap &params, const Passwd &pass)
{
	QSqlDatabase db = QSqlDatabase::database(connName, false);

	db.setDatabaseName(params["dbname"]);
	QStringList hostport = params["host"].split(":");
	if (hostport.size() > 0)
		db.setHostName(hostport[0]);
	if (hostport.size() > 1)
		db.setPort(hostport[1].toInt());
	db.setUserName(params["user"]);
	db.setPassword(pass);

	QString envvar(db.driverName()+ "_OPTIONS");
	const char *opts = getenv(envvar.toLatin1());
	if (opts)
		db.setConnectOptions(opts);

	XSqlQuery::setTablePrefix(params["prefix"]);
	db.open();
	QSqlError e = db.lastError();

	if (e.isValid() || !db.isOpen()) {
		XSqlQuery::clearTablePrefix();
		db.close();
		throw errorEx(e);
	}
	/* This is MySQL specific. Execute it always, because
	 * dbType() could return "ODBC" but connect to MariaDB
	 */
	XSqlQuery q("SET SESSION SQL_MODE='ANSI'");
	q.exec("PRAGMA secure_delete = 'true'");
}

void database_model::openLocalDatabase(const QString &connName,
					const QString &descriptor)
{
	QSqlDatabase db = QSqlDatabase::database(connName);
	XFile f(descriptor);
	qDebug() << connName << descriptor;
	if (!f.exists(descriptor)) {
		f.open(QIODevice::WriteOnly);
		f.setPermissions(QFile::WriteOwner | QFile::ReadOwner);
	}

	if (f.size() != 0) {
		f.open(QIODevice::ReadOnly);
		QByteArray ba = f.read(6);
		qDebug() << "FILE:" << f.fileName() << ba;
		if (ba != "SQLite") {
			throw errorEx(tr("The file '%1' is not an XCA database")
					.arg(f.fileName()));
		}
	}
	f.close();

	db.setDatabaseName(descriptor);
	db.open();
	QSqlError e = db.lastError();
	if (e.isValid()) {
		db.close();
		throw errorEx(e);
	}
}

void database_model::openDatabase(const QString &descriptor, const Passwd &pass)
{
	DbMap params = splitRemoteDbName(descriptor);
	bool isRemote = params.size() == NUM_PARAM;
	QString connName, type = isRemote ? params["type"] : QString("QSQLITE");

	qDebug() << "IS REMOTE?" << params.size() << NUM_PARAM << type << params;
	try {
		Passwd pwd(pass);
		QSqlDatabase db = QSqlDatabase::addDatabase(type);
		connName = db.connectionName();
		if (!isRemote) {
			if (!db.isDriverAvailable("QSQLITE"))
				throw errorEx(tr("No SqLite3 driver available. Please install the qt-sqlite package of your distribution"));
			openLocalDatabase(connName, descriptor);
		} else {
			openRemoteDatabase(connName, params, pwd);
		}
		DbTransaction::setHasTransaction(
			db.driver()->hasFeature(QSqlDriver::Transactions));
	} catch (errorEx &err) {
		QSqlDatabase::removeDatabase(connName);
		throw err;
	}
}

static void pwhash_upgrade()
{
	/* Start automatic update from sha512 to sha512*8000
	 * if the password is correct. The old sha512 hash does
	 * start with 'S', while the new hash starts with T. */

	/* Start automatic update from md5 to salted sha512*8000
	 * if the password is correct. The md5 hash does not
	 * start with 'S' or 'T, but with a hex-digit */
	if (pki_evp::passHash.startsWith("T")) {
		/* Fine, current hash function used. */
		return;
	}
	if (pki_evp::sha512passwd(pki_evp::passwd,
				pki_evp::passHash) == pki_evp::passHash ||
	    pki_evp::md5passwd(pki_evp::passwd) == pki_evp::passHash)
	{
		QString salt = Entropy::makeSalt();
		pki_evp::passHash = pki_evp::sha512passwT(
				pki_evp::passwd, salt);
	}
}

enum open_result database_model::initPass(const QString &dbName, const QString &passhash) const
{
	QString salt, pass;
	enum open_result result = pw_cancel;

	pass_info p(tr("New Password"), tr("Please enter a password, "
			"that will be used to encrypt your private keys "
			"in the database:\n%1").
			arg(compressFilename(dbName)));

	pki_evp::passHash = passhash;
	if (pki_evp::passHash.isEmpty()) {
		result = PwDialog::execute(&p, &pki_evp::passwd, true, true);
		if (result != pw_ok)
			return result;
		salt = Entropy::makeSalt();
		pki_evp::passHash =pki_evp::sha512passwT(pki_evp::passwd,salt);
		Settings["pwhash"] = pki_evp::passHash;
	} else {
		pwhash_upgrade();
		while (pki_evp::sha512passwT(pki_evp::passwd, pki_evp::passHash)
				!= pki_evp::passHash)
		{
			if (result == pw_ok)
				XCA_PASSWD_ERROR();
			p.setTitle(tr("Password"));
			p.setDescription(tr("Please enter the password for unlocking the database:\n%1").arg(compressFilename(dbName)));
			result = PwDialog::execute(&p, &pki_evp::passwd,
						false, true);
			if (result != pw_ok) {
				pki_evp::passwd = QByteArray();
				return result;
			}
			pwhash_upgrade();
		}
	}
	if (pki_evp::passwd.isNull())
		pki_evp::passwd = "";
	return pw_ok;
}

void database_model::pkiChangedSlot(pki_base *pki)
{
	emit pkiChanged(pki);
}
