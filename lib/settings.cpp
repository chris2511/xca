/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "settings.h"
#include "func.h"
#include "sql.h"
#include "pki_key.h"
#include "digest.h"
#include "pki_pkcs12.h"
#include "pki_export.h"

#include <QDir>
#include <QFile>
#include <openssl/asn1.h>

settings Settings;

svalue::svalue(settings *s, const QString &k)
	:  setting(s), key(k)
{
}

QString svalue::get() const
{
	return setting ? setting->get(key) : QString();
}

void svalue::set(const QString &val)
{
	if (setting)
		setting->set(key, val);
}

settings::settings()
{
	hostspecific = QStringList({ "pkcs11path", "workingdir", "mw_geometry" });
}

const QMap<QString, QString> settings::defaults() const
{
	return QMap<QString, QString> {
		{ "mandatory_dn", "" },
		{ "explicit_dn", "C,ST,L,O,OU,CN,emailAddress" },
		{ "string_opt", "MASK:0x2002" },
		{ "workingdir", getHomeDir() + "/" },
		{ "default_hash", digest::getDefault().name() },
		{ "pkcs12_enc_algo", encAlgo::getDefault().name() },
		{ "ical_expiry", "1W" },
		{ "cert_expiry", "80%" },
		{ "serial_len", "64" },
		{ "fp_separator", ":" },
		{ "fp_digits", "2" },
		{ "hide_unusable", "no" },
		{ "KeyFormat", QString::number(DEFAULT_KEY_CLIPBOARD_TYPE) },
		{ "CertFormat", QString::number(DEFAULT_CERT_CLIPBOARD_TYPE) },
	};
}

void settings::clear()
{
	loaded = false;
	values.clear();
	db_keys.clear();
	const QMap<QString, QString> def = defaults();
	for(QString key : def.keys())
		setAction(key, def[key]);
}

void settings::setAction(const QString &key, const QString &value)
{
	if (key == "string_opt")
		ASN1_STRING_set_default_mask_asc((char*)CCHAR(value));
	else if (key == "default_hash")
		digest::setDefault(value);
	else if (key == "pkcs12_enc_algo")
		encAlgo::setDefault(value);
	else if (key == "defaultkey")
		keyjob::defaultjob = keyjob(value);
	else if (key == "optionflags") {
		XSqlQuery q;
		Transaction;
		if (!TransBegin())
			return;
		SQL_PREPARE(q, "DELETE FROM settings where key_='optionflags'");
		q.exec();
		foreach(QString flag, value.split(",")) {
			if (flag == "dont_colorize_expiries")
				flag = "no_expire_colors";
			setAction(flag, "yes");
		}
		TransCommit();
		return;
	}
	values[key] = value;
}

QString settings::defaults(const QString &key)
{
	return defaults()[key];
}

void settings::load_settings()
{
	if (loaded || !QSqlDatabase::database().isOpen())
		return;
	XSqlQuery q("SELECT key_, value FROM settings");
	while (q.next()) {
		QString key = q.value(0).toString().simplified();
		QString value = q.value(1).toString();
		QStringList l = key.split(":");
		if (l.size() == 2 && l[1] != hostId())
			continue;	// Skip key with non-matching host ID
		if (l[0] == "workingdir") {
			if (!QDir(value).exists())
				continue; // Skip non-existing working-dir
			if (!value.isEmpty() && !value.endsWith("/"))
				value += "/";
			if (value.isEmpty())
				value = getHomeDir() + "/";
		}
		db_keys << key;		// Key with host ID
		setAction(l[0], value);	// Key without host ID
	}
	loaded = true;
}

QString settings::get(QString key)
{
	load_settings();
	if (key == "schema" && QSqlDatabase::database().isOpen()) {
		XSqlQuery q("SELECT value FROM settings WHERE key_='schema'");
		if (q.first())
			setAction("schema", q.value(0).toString());
	}
	return values.contains(key) ? values[key] : QString();
}

void settings::set(QString key, QString value)
{
	XSqlQuery q;
	load_settings();
	QString origkey = key;

	if (key == "workingdir") {
		if (!QDir(value).exists())
			return;
		value = relativePath(value);
		if (!value.isEmpty() && !value.endsWith("/"))
			value += "/";
	}
	if (hostspecific.contains(key))
		key += QString(":%1").arg(hostId());
	if (db_keys.contains(key) && values[origkey] == value)
		return;

	Transaction;
	if (!TransBegin())
		return;

	if (db_keys.contains(key)) {
		SQL_PREPARE(q, "UPDATE settings SET value=? WHERE key_=?");
	} else {
		SQL_PREPARE(q, "INSERT INTO settings (value, key_) VALUES (?,?)");
		db_keys << key;
	}
	q.bindValue(0, value);
	q.bindValue(1, key);
	q.exec();
	setAction(origkey, value);
	TransCommit();
}
