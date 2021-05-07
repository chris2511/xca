/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <signal.h>

#include <QDir>
#include <QDebug>

#include "widgets/MainWindow.h"
#include "widgets/XcaApplication.h"
#include "widgets/XcaWarning.h"
#include "func.h"
#include "xfile.h"
#include "main.h"
#include "entropy.h"
#include "settings.h"
#include "database_model.h"
#include "pki_multi.h"
#include "pki_evp.h"
#include "pki_base.h"
#include "arguments.h"
#include "db_x509.h"
#if defined(Q_OS_WIN32)
//For the segfault handler
#include <windows.h>
#endif

char segv_data[1024];
MainWindow *mainwin = NULL;

static int debug;

#if defined(Q_OS_WIN32)
static LONG CALLBACK w32_segfault(LPEXCEPTION_POINTERS e)
{
	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		if (segv_data[0]) {
			XCA_WARN(QString(segv_data));
			abort();
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	} else
		return EXCEPTION_CONTINUE_SEARCH;
}
#else
static void segv_handler_gui(int)
{
	if (segv_data[0])
		XCA_WARN(QString(segv_data));
	abort();
}
#endif

void myMsgOutput(QtMsgType type, const char *msg)
{
	static QElapsedTimer *t;
	static int abort_on_warning = -1;
	const char *severity = "Unknown", *warn_msg = NULL;
	int el;

	if (!t) {
		char *d = getenv("XCA_DEBUG");
		t = new QElapsedTimer();
		t->start();
		if (d && *d)
			debug = 1;
	}
	if (abort_on_warning == -1) {
		char *a = getenv("XCA_ABORT_ON_WARNING");
		abort_on_warning = a && *a;
	}
	el = t->elapsed();
	switch (type) {
	case QtDebugMsg:
		if (!debug)
			return;
		severity = COL_CYAN "Debug";
		break;
	case QtWarningMsg:  warn_msg = "WARNING";  severity = COL_LRED "Warning"; break;
	case QtCriticalMsg: warn_msg = "CRITICAL"; severity = COL_RED "Critical"; break;
	case QtFatalMsg:    warn_msg = "FATAL";    severity = COL_RED "Fatal"; break;
#if QT_VERSION >= 0x050000
	case QtInfoMsg:	    severity = COL_CYAN "Info"; break;
#endif
	default:            severity = COL_CYAN "Default"; break;
	}
	console_write(stderr, QString(COL_YELL "%1%2 %3:" COL_RESET " %4\n")
			.arg(el/1000, 4)
			.arg((el%1000)/100, 2, 10, QChar('0'))
			.arg(severity).arg(QString::fromUtf8(msg)).toUtf8());

	if (abort_on_warning == 1 && warn_msg) {
		qFatal("Abort on %s", warn_msg);
	}
}

#if QT_VERSION >= 0x050000
void myMessageOutput(QtMsgType t, const QMessageLogContext &, const QString &m)
{
	myMsgOutput(t, m.toUtf8().constData());
}
#endif

static void cmd_version(FILE *fp)
{
	console_write(fp, QString(XCA_TITLE "\nVersion %1\n")
				.arg(version_str(false)).toUtf8());
}

const char *xca_name = "xca";
static void cmd_help(int exitcode = EXIT_SUCCESS, const char *msg = NULL)
{
	FILE *fp = exitcode == EXIT_SUCCESS ? stdout : stderr;
	QString s;

	cmd_version(fp);
	s = QString("\nUsage %1 <options> <file-to-import> ...\n\n%2\n")
				.arg(xca_name).arg(arguments::help());
	if (msg)
		s += QString("\nError: %1\n").arg(msg);

	console_write(fp, s.toUtf8());
	exit(exitcode);
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

static pki_multi *cmdline_items;
static void read_cmdline(int argc, char *argv[])
{
	arguments cmd_opts(argc, argv);
	pki_evp::passwd = acquire_password(cmd_opts["password"]);
	Passwd sqlpw = acquire_password(cmd_opts["sqlpass"]);

	if (cmd_opts.has("verbose"))
		debug = 1;

	if (cmd_opts.getResult() != 0)
		cmd_help(EXIT_FAILURE, cmd_opts.resultString().toUtf8());

	if (cmd_opts.has("database"))
		Database.open(cmd_opts["database"], sqlpw);

	cmdline_items = new pki_multi();

	foreach(QString file, cmd_opts.getFiles()) {
		qDebug() << "Probe" << file;
		cmdline_items->probeAnything(file);
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
			cmd_help(EXIT_FAILURE, CCHAR(err.getString()));
		} catch (enum open_result opt) {
			static const char * const msg[] = {
				/* pw_cancel */ "Password input aborted",
				/* pw_ok     */ "Password accepted??",
				/* pw_exit   */ "Exit selected",
				/* open_abort*/ "No database given",
			};
			cmd_help(EXIT_FAILURE, msg[opt]);
		}
	}
	if (cmd_opts.has("list-curves")) {
		QStringList list;
		foreach(const builtin_curve &c, builtinCurves) {
			list << QString(COL_YELL "%1" COL_RESET "%2")
					.arg(OBJ_nid2sn(c.nid), -26)
					.arg(c.comment);
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
		foreach(pki_x509 *iss, issuers) {
			pki_key *key = iss->getRefKey();
			QString keytype = key ? key->getTypeString() : "";
			out << QString("%1 '%2' %3")
				.arg(iss->getSqlItemId().toULongLong(), 4)
				.arg(iss->getIntName())
				.arg(keytype);
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
			pki_crl *crl = crls->newCrl(task);
			if (crl)
				cmdline_items->append_item(crl);
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
		cmdline_items = NULL;
	}
}

int main(int argc, char *argv[])
{
	const char *xca_special = getenv("XCA_SPECIAL");
	if (xca_special && *xca_special) {
		puts(CCHAR(arguments::doc(xca_special)));
		return 0;
	}
#if QT_VERSION < 0x050000
	qInstallMsgHandler(myMsgOutput);
#else
	qInstallMessageHandler(myMessageOutput);
#endif
#if defined(Q_OS_WIN32)
	AttachConsole(-1);

	int wargc;
	wchar_t **wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
	if (wargv && wargc) {
		int i;
		if (argc != wargc)
			qWarning() << "argc != wargc" << argc << wargc;
		if (argc > wargc)
			argc = wargc;
		qDebug() << "wargc" << wargc << argc;
		for (i = 0; i < argc; i++) {
			QString s = QString::fromWCharArray(wargv[i]);
			QByteArray ba = s.toUtf8();
			argv[i] = strdup(ba.constData());
			qDebug() << "wargv" << i << argv[i] << s;
		}
		argv[i] = NULL;
		LocalFree(wargv);
	}
	SetUnhandledExceptionFilter(w32_segfault);
#else
	signal(SIGSEGV, segv_handler_gui);
#endif
	if (argc > 0)
		xca_name = argv[0];

	bool console_only = arguments::is_console(argc, argv);
	XcaApplication *gui;

#if !defined(Q_OS_WIN32)
	if (console_only) {
		new QCoreApplication(argc, argv);
		gui = NULL;
	} else
#endif
	{
		/* On windows, always instantiate a GUI app */
		gui = new XcaApplication(argc, argv);
	}

	if (!QDir().mkpath(getUserSettingsDir()))
		qCritical("Failed to create Path: '%s'", CCHAR(getUserSettingsDir()));

	Entropy entropy;
	Settings.clear();
	initOIDs();

	for (int i=0; i < argc; i++)
		qDebug() << "wargv" << argc << i << argv[i];
	try {
		if (gui && !console_only) {
			mainwin = new MainWindow();
			gui->setMainwin(mainwin);
			read_cmdline(argc, argv);
			mainwin->importMulti(cmdline_items, 1);
			cmdline_items = NULL;
			if (!Database.isOpen())
				mainwin->init_database(QString());
			else
				mainwin->setup_open_database();
			mainwin->show();
			gui->exec();
		} else {
			read_cmdline(argc, argv);
			delete cmdline_items;
		}
	} catch (errorEx &ex) {
		XCA_ERROR(ex);
	} catch (enum open_result r) {
		qDebug() << "DB open failed: " << r;
	}
	Database.close();

	qDebug() << "pki_base::count" << pki_base::allitems.size();
	foreach(pki_base *pki, pki_base::allitems)
		qDebug() << "Remaining" << pki->getClassName()
			 << pki->getIntName();
	delete mainwin;
	delete gui;
#if defined(Q_OS_WIN32)
	FreeConsole();
#endif
	return EXIT_SUCCESS;
}
