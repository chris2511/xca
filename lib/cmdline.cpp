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
#include "pki_x509req.h"
#include "db_x509req.h"
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

/* Find an item of type T in the database by SQL item id or internal name */
template <class T> static T *lookup_item(const QString &needle)
{
	bool ok;
	qulonglong id = needle.toULongLong(&ok);
	T *pki = ok ? Store.lookupPki<T>(QVariant(id)) : NULL;
	if (pki)
		return pki;
	foreach(pki_base *p, Store.getAll<pki_base>()) {
		T *c = dynamic_cast<T *>(p);
		if (c && c->getIntName() == needle)
			return c;
	}
	return NULL;
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

	if (cmd_opts.has("no-native-dialogs"))
		QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, true);

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
	if (cmd_opts.has("revoke") || cmd_opts.has("unrevoke")) {
		bool revoke = cmd_opts.has("revoke");
		QString what = cmd_opts[revoke ? "revoke" : "unrevoke"];
		pki_x509 *cert = lookup_item<pki_x509>(what);
		pki_x509 *signer = cert ? cert->getSigner() : NULL;

		if (!cert) {
			XCA_ERROR(QObject::tr("Certificate '%1' not found")
					.arg(what));
		} else if (!signer) {
			XCA_ERROR(QObject::tr("Certificate '%1' has no issuer")
					.arg(cert->getIntName()));
		} else if (revoke) {
			QString reason = cmd_opts["reason"];
			x509rev rev;

			rev.setSerial(cert->getSerial());
			rev.setDate(a1time());
			if (!reason.isEmpty()) {
				if (!x509rev::crlreasons().contains(reason)) {
					Database.close();
					throw errorEx(QObject::tr(
						"Unknown revocation reason '%1'")
						.arg(reason));
				}
				rev.setReason(reason);
			}
			cert->setRevoked(rev);
			x509revList revlist;
			revlist << rev;
			signer->mergeRevList(revlist);
			XCA_INFO(QObject::tr("Certificate '%1' revoked")
					.arg(cert->getIntName()));
		} else {
			x509rev rev;

			rev.setSerial(cert->getSerial());
			cert->setRevoked(x509rev());
			x509revList revList = signer->getRevList();
			int i = revList.indexOf(rev);
			if (i != -1)
				revList.takeAt(i);
			signer->setRevocations(revList);
			XCA_INFO(QObject::tr(
				"Revocation of certificate '%1' removed")
				.arg(cert->getIntName()));
		}
	}
	if (cmd_opts.has("sign-req")) {
		QString reqid = cmd_opts["sign-req"];
		QString signerid = cmd_opts["signer"];
		db_x509 *certs = Database.model<db_x509>();
		pki_x509req *req = lookup_item<pki_x509req>(reqid);
		pki_x509 *signer = signerid.isEmpty() ? NULL :
					lookup_item<pki_x509>(signerid);

		if (!req) {
			XCA_ERROR(QObject::tr("Request '%1' not found")
					.arg(reqid));
		} else if (!signer) {
			XCA_ERROR(QObject::tr("Signer '%1' not found")
					.arg(signerid));
		} else if (!signer->canSign()) {
			XCA_ERROR(QObject::tr(
				"'%1' is not a CA with an associated private key")
				.arg(signer->getIntName()));
		} else {
			signjob task(req, signer);
			QString hash = cmd_opts["hash"];
			QString days = cmd_opts["days"];
			pki_key *signkey = signer->getPubKey();

			if (signkey) {
				task.hashAlgo.adjust(signkey->possibleHashNids());
				delete signkey;
			}
			if (!hash.isEmpty()) {
				task.hashAlgo = digest(hash);
				if (task.hashAlgo.name().isEmpty()) {
					Database.close();
					throw errorEx(QObject::tr(
						"Unknown hash algorithm '%1'")
						.arg(hash));
				}
			}
			if (!days.isEmpty()) {
				bool ok;
				int d = days.toInt(&ok);
				if (!ok || d < 1) {
					Database.close();
					throw errorEx(QObject::tr(
						"Invalid value for 'days': '%1'")
						.arg(days));
				}
				task.notAfterDays = d;
			}
			task.copyReqExt = cmd_opts.has("copy-req-ext");
			pki_x509 *cert = certs->newCert(task, cmd_opts["name"]);
			if (cert)
				cmdline_items->append_item(cert);
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

	BioByteArray bba, bbafile;
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
		if (cmd_opts.has("pem-file"))
			pki->print(bbafile, pki_base::print_pem);
		else if (cmd_opts.has("pem"))
			pki->print(bba, pki_base::print_pem);
	}
	if (bba.size() > 0)
		console_write(stdout, bba);

	if (bbafile.size() > 0)
	{
		QString filename = cmd_opts["pem-file"];
		XFile f(filename);
		if (f.open_write())
			f.write(bbafile);
		else
			XCA_ERROR(QObject::tr("Failed to write PEM data to '%1'")
					.arg(filename));
		f.close();
	}
	if (cmd_opts.has("import")) {
		Database.insert(cmdline_items);
		*_cmdline_items = nullptr;
	}
	return EXIT_SUCCESS;
}

