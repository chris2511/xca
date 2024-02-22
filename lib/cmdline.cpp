/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QString>
#include <QFile>
#include <stdio.h>

#include "func.h"
#include "database_model.h"
#include "debug_info.h"
#include "pki_multi.h"
#include "pki_evp.h"
#include "pki_base.h"
#include "pki_x509.h"
#include "pki_crl.h"
#include "arguments.h"
#include "pki_export.h"
#include "PwDialogCore.h"
#include "BioByteArray.h"
#include "db_x509.h"
#include "db_crl.h"

static const char *xca_name = "xca";
static void cmd_version(FILE *fp)
{
	console_write(fp, QString(XCA_TITLE "\nVersion %1\n")
				.arg(version_str(false)).toUtf8());
}

static int cmd_help(int exitcode = EXIT_SUCCESS, const char *msg = NULL)
{
	FILE *fp = exitcode == EXIT_SUCCESS ? stdout : stderr;
	QString s;

	cmd_version(fp);
	s = QString("\nUsage %1 <options> <file-to-import> ...\n\n%2\n")
				.arg(xca_name).arg(arguments::help());
	if (msg)
		s += QString("\nError: %1\n").arg(msg);

	console_write(fp, s.toUtf8());
	return exitcode;
}

static Passwd acquire_password(QString source)
{
	Passwd pass;
	pass.append(source.toUtf8());

	if (source == "stdin")
		source = "fd:0";
	if (source.startsWith("pass:")) {
		pass = source.mid(5).toLatin1();
	} else if (source.startsWith("file:")) {
		XFile f(source.mid(5));
		f.open_read();
		pass = f.readLine(128).trimmed();
	} else if (source.startsWith("env:")) {
		pass = getenv(source.mid(4).toLocal8Bit());
	} else if (source.startsWith("fd:")) {
		int fd = source.mid(3).toInt();
		QFile f;
		f.open(fd, QIODevice::ReadOnly);
		pass = f.readLine(128).trimmed();
	}
	return pass;
}

static bool compare_pki_base(pki_base* a, pki_base* b)
{
	return (a->getSqlItemId().toULongLong() <
		b->getSqlItemId().toULongLong());
}

int read_cmdline(int argc, char *argv[], bool console_only,
			pki_multi **_cmdline_items)
{
	pki_multi *cmdline_items;

	if (argc > 0)
		xca_name = argv[0];
	arguments cmd_opts(argc, argv);
	PwDialogCore::cmdline_passwd = acquire_password(cmd_opts["password"]);
	Passwd sqlpw = acquire_password(cmd_opts["sqlpass"]);

	if (cmd_opts.has("verbose")) {
		QString all = cmd_opts["verbose"];
		debug_info::set_debug(all.isEmpty() ? QString("all") : all);
	}
	if (console_only)
		database_model::open_without_password = true;

	if (cmd_opts.has("database"))
		Database.open(cmd_opts["database"], sqlpw);

	*_cmdline_items = cmdline_items = new pki_multi();

	foreach(QString file, cmd_opts.getFiles()) {
		qDebug() << "Probe" << file;
		cmdline_items->probeAnything(file);
	}
	QStringList names = cmd_opts["import-names"].split(";");
	foreach(pki_base *pki, cmdline_items->get()) {
		if (names.isEmpty())
			break;
		QString name = names.takeFirst();
		if (!name.isEmpty())
			pki->setIntName(name);
	}
	if (cmdline_items->failed_files.size() > 0) {
		XCA_WARN(QString("Failed to import from '%1'")
			.arg(cmdline_items->failed_files.join("' '")));
	}
	if (cmd_opts.needDb() && !Database.isOpen()) {
		/* We need a database for the following operations
		 * but there is none, yet. Try the default database */
		try {
			Database.open(QString());
		} catch (errorEx &err) {
			return cmd_help(EXIT_FAILURE, CCHAR(err.getString()));
		} catch (enum open_result opt) {
			static const char * const msg[] = {
				/* pw_cancel */ "Password input aborted",
				/* pw_ok     */ "Password accepted??",
				/* pw_exit   */ "Exit selected",
				/* open_abort*/ "No database given",
			};
			return cmd_help(EXIT_FAILURE, msg[opt]);
		}
	}
	database_model::open_without_password = false;

	if (cmd_opts.has("list-curves")) {
		QStringList list;
		foreach(const builtin_curve &c, builtinCurves) {
			list << QString(COL_YELL "%1" COL_RESET "%2")
					.arg(OBJ_nid2sn(c.nid), -26)
					.arg(c.comment);
		}
		console_write(stdout, list.join("\n").toUtf8() + '\n');
	}
	if (cmd_opts.has("list-items")) {
		QStringList list;
		QList<pki_base*> items = Store.getAll<pki_base>();
		std::sort(items.begin(), items.end(), compare_pki_base);
		foreach(pki_base *pki, items) {
			list << QString(COL_YELL "%1 " COL_GREEN "%2 "
					COL_RESET "%3")
					.arg(pki->getSqlItemId().toString(), 7)
					.arg(pki->getTypeString(), -27)
					.arg(pki->getIntName());
		}
		console_write(stdout, list.join("\n").toUtf8() + '\n');
	}
	if (!cmd_opts["index"].isEmpty()) {
		qDebug() << cmd_opts["index"];
		db_x509 *certs = Database.model<db_x509>();
		certs->writeIndex(cmd_opts["index"], false);
		XCA_INFO(QObject::tr("Index file written to '%1'")
					.arg(cmd_opts["index"]));
	}
	if (!cmd_opts["hierarchy"].isEmpty()) {
		qDebug() << cmd_opts["hierarchy"];
		db_x509 *certs = Database.model<db_x509>();
		certs->writeIndex(cmd_opts["hierarchy"], true);
		XCA_INFO(QObject::tr("Index hierarchy written to '%1'")
					.arg(cmd_opts["hierarchy"]));
	}
	if (cmd_opts.has("help"))
		cmd_help();

	if (cmd_opts.has("version"))
		cmd_version(stdout);

	if (cmd_opts.has("keygen")) {
		keyjob task(cmd_opts["keygen"]);
		if (!task.isValid()) {
			Database.close();
			throw errorEx(QObject::tr("Unknown key type %1")
					.arg(cmd_opts["keygen"]));
		}
		db_key *keys = Database.model<db_key>();
		pki_key *pki = keys->newKey(task, cmd_opts["name"]);
		if (pki)
			cmdline_items->append_item(pki);
	}
	if (cmd_opts.has("issuers")) {
		QStringList out;
		db_x509 *certs = Database.model<db_x509>();
		QList<pki_x509*>issuers = certs->getAllIssuers();
		std::sort(issuers.begin(), issuers.end(), compare_pki_base);
		foreach(pki_x509 *iss, issuers) {
			pki_key *key = iss->getRefKey();
			QString keytype = key ? key->getTypeString() : "";
			out << QString(COL_YELL "%1 " COL_GREEN "%2 "
					COL_RESET "%3")
				.arg(iss->getSqlItemId().toULongLong(), 7)
				.arg(keytype, -13)
				.arg(iss->getIntName());
		}
		console_write(stdout, out.join("\n").toUtf8() + '\n');
	}
	if (cmd_opts.has("crlgen")) {
		db_crl *crls = Database.model<db_crl>();
		db_x509 *certs = Database.model<db_x509>();
		QList<pki_x509*>issuers = certs->getAllIssuers();
		pki_x509 *issuer = NULL;
		QString ca = cmd_opts["crlgen"];
		foreach(pki_x509 *iss, issuers) {
			if (iss->getIntName() == ca ||
			    iss->getSqlItemId().toString() == ca)
			{
				issuer = iss;
				break;
			}
		}
		if (!issuer) {
			XCA_ERROR(QString("Issuer '%1' not found")
					.arg(cmd_opts["crlgen"]));
		} else {
			crljob task(issuer);
			pki_crl *crl = crls->newCrl(task, cmd_opts["name"]);
			if (crl)
				cmdline_items->append_item(crl);
		}
	}
	if (!cmd_opts["select"].isEmpty()) {
		foreach(QString item, cmd_opts["select"].split(",")) {
			bool ok;
			qDebug() << "Select" << item;
			qulonglong id = item.toULongLong(&ok);
			pki_base *pki = Store.lookupPki<pki_base>(QVariant(id));
			if (pki)
				cmdline_items->append_item(pki);
		}
	}

	BioByteArray bba;
	foreach(pki_base *pki, cmdline_items->get()) {
		QString filename = pki->getFilename();
		if ((cmd_opts.has("text") || cmd_opts.has("print")) &&
		    filename.size() > 0)
		{
			bba += QString("\n" COL_GREEN COL_UNDER "File: %1"
				COL_RESET "\n").arg(filename).toUtf8();
		}
		if (cmd_opts.has("print"))
			pki->print(bba, pki_base::print_coloured);
		if (cmd_opts.has("text"))
			pki->print(bba, pki_base::print_openssl_txt);
		if (cmd_opts.has("pem"))
			pki->print(bba, pki_base::print_pem);
	}
	if (bba.size() > 0)
		console_write(stdout, bba);
	if (cmd_opts.has("import")) {
		Database.insert(cmdline_items);
		*_cmdline_items = nullptr;
	}
	return EXIT_SUCCESS;
}

