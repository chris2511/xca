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
	static QTime *t;
	if (!t) {
		char *d = getenv("XCA_DEBUG");
		t = new QTime();
		t->start();
		if (d && *d)
			debug = 1;
	}
	int el = t->elapsed();
	const char *severity = "Unknown";
	switch (type) {
	case QtDebugMsg:
		if (!debug)
			return;
		severity = COL_CYAN "Debug";
		break;
	case QtWarningMsg:  severity = COL_LRED "Warning"; break;
	case QtCriticalMsg: severity = COL_RED "Critical"; break;
	case QtFatalMsg:    severity = COL_RED "Fatal"; break;
#if QT_VERSION >= 0x050000
	case QtInfoMsg:	    severity = COL_CYAN "Info"; break;
#endif
	default:            severity = COL_CYAN "Default"; break;
	}

	fprintf(stderr, COL_YELL "% 4d.%02d %s:" COL_RESET " %s\n",
			 el/1000, (el%1000)/100, severity, msg);
}

#if QT_VERSION >= 0x050000
void myMessageOutput(QtMsgType t, const QMessageLogContext &, const QString &m)
{
	myMsgOutput(t, CCHAR(m));
}
#endif

QCoreApplication *createApplication(int &argc, char *argv[])
{
	if (arguments::is_console(argc, argv))
		return new QCoreApplication(argc, argv);

	return new XcaApplication(argc, argv);
}

static void cmd_version(FILE *fp)
{
	fprintf(fp, XCA_TITLE "\nVersion %s\n", version_str(false));
}

const char *xca_name = "xca";
static void cmd_help(int exitcode = EXIT_SUCCESS, const char *msg = NULL)
{
	FILE *fp = exitcode == EXIT_SUCCESS ? stdout : stderr;

	cmd_version(fp);
	fprintf(fp, "\nUsage %s <options> <file-to-import> ...\n\n", xca_name);
	fputs(CCHAR(arguments::help()), fp);

	if (msg)
		fprintf(stderr, "\nCmdline Error: %s\n", msg);

	exit(exitcode);
}

static Passwd acquire_password(const QString &source)
{
	Passwd pass;
	pass.append(source);

	if (source.startsWith("pass:")) {
		pass = source.mid(5).toLatin1();
	} else if (source.startsWith("file:")) {
		XFile f(source.mid(5));
		f.open_read();
		pass = f.readLine(128).trimmed();
	} else if (source.startsWith("env:")) {
		pass = getenv(source.mid(4).toLocal8Bit());
	}
	return pass;
}

static pki_multi *imported_items;
static database_model* read_cmdline(int argc, char *argv[])
{
	arguments cmd_opts(argc, argv);
	database_model *models = NULL;
	pki_evp::passwd = acquire_password(cmd_opts["password"]);
	Passwd sqlpw = acquire_password(cmd_opts["sqlpass"]);
	if (cmd_opts.has("verbose"))
		debug = 1;

	if (cmd_opts.getResult() == '?')
		cmd_help(EXIT_FAILURE);

	if (cmd_opts.has("database"))
		models = new database_model(cmd_opts["database"], sqlpw);

	imported_items = new pki_multi();

	foreach(QString file, cmd_opts.getFiles())
		imported_items->probeAnything(file);

	if (cmd_opts.needDb() && !models) {
		/* We need a database for the following operations
		 * but there is none, yet. Try the default database */
		try {
			models = new database_model(QString());
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
	if (!cmd_opts["index"].isEmpty()) {
		qDebug() << cmd_opts["index"];
		db_x509 *certs = models->model<db_x509>();
		certs->writeIndex(cmd_opts["index"], false);
	}
	if (!cmd_opts["index-hierarchy"].isEmpty()) {
		qDebug() << cmd_opts["index-hierarchy"];
		db_x509 *certs = models->model<db_x509>();
		certs->writeIndex(cmd_opts["index-hierarchy"], true);
	}
	if (cmd_opts.has("help"))
		cmd_help();
	if (cmd_opts.has("version"))
		cmd_version(stdout);

	FILE *fp = stdout;
	pki_base *pki;
	while ((pki = imported_items->pull())) {
		QString filename = pki->getFilename();
		if ((cmd_opts.has("text") || cmd_opts.has("print")) &&
		    filename.size() > 0)
		{
			fprintf(fp, "\n" COL_GREEN COL_UNDER "File: %s"
				COL_RESET "\n", CCHAR(filename));
		}
		if (cmd_opts.has("print"))
			pki->print(fp, pki_base::print_coloured);
		if (cmd_opts.has("text"))
			pki->print(fp, pki_base::print_openssl_txt);
		if (cmd_opts.has("pem"))
			pki->print(fp, pki_base::print_pem);
	}
	return models;
}

int main(int argc, char *argv[])
{
	if (argc > 0)
		xca_name = argv[0];

#if defined(Q_OS_WIN32)
	SetUnhandledExceptionFilter(w32_segfault);
#else
	signal(SIGSEGV, segv_handler_gui);
#endif

	QDir().mkpath(getUserSettingsDir());

#if QT_VERSION < 0x050000
	qInstallMsgHandler(myMsgOutput);
#else
	qInstallMessageHandler(myMessageOutput);
#endif
	Entropy entropy;

	Settings.clear();

	QCoreApplication *core = createApplication(argc, argv);
	XcaApplication *gui = qobject_cast<XcaApplication*>(core);

	try {
		database_model *models = read_cmdline(argc, argv);
		if (gui) {
			mainwin = new MainWindow(models);
			gui->setMainwin(mainwin);
			mainwin->importMulti(imported_items, 1);
			imported_items = NULL;
			mainwin->show();
			gui->exec();
		} else {
			delete models;
		}

	} catch (errorEx &ex) {
		XCA_ERROR(ex);
	} catch (enum open_result r) {
		XCA_ERROR(QObject::tr("DB Open failed: %1").arg(r));
	}
	qDebug() << "pki_base::count" << pki_base::allitems.size();
	foreach(pki_base *pki, pki_base::allitems)
		qDebug() << "Remaining" << typeid(*pki).name() << pki->getIntName();
	delete mainwin;
	delete gui;

	return EXIT_SUCCESS;
}
