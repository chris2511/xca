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
#include "ui_MainWindow.h"
#include "widgets/XcaApplication.h"
#include "XcaWarningCore.h"
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
#include "pki_export.h"
#include "db_x509.h"
#if defined(Q_OS_WIN32)
//For the segfault handler
#include <windows.h>
#endif

#include <QTextStream>

void migrateOldPaths();

char segv_data[1024];
MainWindow *mainwin = NULL;

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

class dbg_pattern
{
		QString file, func;
		unsigned first, last;
		bool inv;
	public:
		bool invert() const { return inv; }
		dbg_pattern(QString);
		bool match(const QString &curr_file, const QString &curr_func,
					int line) const;
};

class debug_info
{
	private:
		QString short_file;
		QString short_func;
		int line;

		static QList<dbg_pattern> patternlist;
	public:
		static bool all;
		static void set_debug(const QString &dbg);
		debug_info(const QMessageLogContext &c);
		QString log_prefix() const;
		bool do_debug() const;
		static bool isEmpty()
		{
			return patternlist.size() == 0;
		}
};

QList<dbg_pattern> debug_info::patternlist;
bool debug_info::all = false;

dbg_pattern::dbg_pattern(QString part)
	: first(0), last(INT_MAX), inv(false)
{
	bool ok;
	if (part[0] == '-') {
		inv = true;
		part.remove(0, 1);
	}
	file = func = part;
	QStringList file_num = part.split(":");
	if (file_num.size() == 2) {
		file = file_num[0];
		file_num = file_num[1].split("-");
		if (file_num.size() == 1) {
			first = last = file_num[0].toUInt();
		} else {
			if (!file_num[0].isEmpty()) {
				first = file_num[0].toUInt(&ok);
				Q_ASSERT(ok);
			}
			if (!file_num[1].isEmpty()) {
				last = file_num[1].toUInt(&ok);
				Q_ASSERT(ok);
			}
		}
	}
	qDebug() << "New debug match" << (inv ? "Not" : "") << file << func << first << last;
}

bool dbg_pattern::match(const QString &curr_file, const QString &curr_func,
						int line) const
{
	// QTextStream out(stdout);
	// out << QString("MATCH %1:%2(%3)\n").arg(curr_file).arg(curr_func).arg(line);
	if (curr_func == func)
		return true;
	if (curr_func.endsWith(QString("::%1").arg(func)))
		return true;
	if (curr_file != file && !file.endsWith(QString("/%1").arg(curr_file)))
		return false;
	if (line >= first && line <= last)
		return true;
	return false;
}

void debug_info::set_debug(const QString &dbg)
{
	bool local_all = false;
	all = true;
	if (isEmpty()) {
		foreach(QString part, dbg.split(",")) {
			if (part.toLower() == "all") {
				local_all = true;
				continue;
			}
			dbg_pattern d(part);
			patternlist.insert(d.invert() ? 0 : patternlist.size(), d);
		}
	}
	all = local_all;
}

debug_info::debug_info(const QMessageLogContext &ctx)
	: line(0)
{
	line = ctx.line;
	if (ctx.file && ctx.line) {
		int pos;
		short_file = ctx.file, short_func = ctx.function;
		pos = short_file.lastIndexOf("/");
		short_file.remove(0, pos +1);
		pos = short_func.indexOf("(");
		short_func.remove(pos, short_func.size());
		pos = short_func.lastIndexOf(" ");
		short_func.remove(0, pos +1);
	}
	//std::cerr << "DBG '" << (ctx.function ?: "(NULL)" )<< "' '" << CCHAR(short_func) << "' " << std::endl;
}

QString debug_info::log_prefix() const
{
	if (short_file == nullptr && line == 0)
		return QString();
	return QString(" " COL_MAGENTA "%1" COL_GREEN COL_BOLD ":%2 " COL_BLUE "%3")
					.arg(short_file).arg(line).arg(short_func);
}

bool debug_info::do_debug() const
{
	foreach(dbg_pattern pattern, patternlist) {
		if (pattern.match(short_file, short_func, line))
			return !pattern.invert();
	}
	return all;
}

void myMessageOutput(QtMsgType type, const QMessageLogContext &ctx,
			const QString &msg)
{
	static QElapsedTimer *t;
	static int abort_on_warning = -1;
	const char *severity = "Unknown", *warn_msg = NULL;
	int el;

	if (!t) {
		t = new QElapsedTimer();
		t->start();
	}
	if (abort_on_warning == -1) {
		char *a = getenv("XCA_ABORT_ON_WARNING");
		abort_on_warning = a && *a;
	}
	debug_info dinfo(ctx);
	el = t->elapsed();
	switch (type) {
	case QtDebugMsg:
		if (!dinfo.do_debug())
			return;
		severity = COL_CYAN "Debug";
		break;
	case QtWarningMsg:  warn_msg = "WARNING";  severity = COL_LRED "Warning"; break;
	case QtCriticalMsg: warn_msg = "CRITICAL"; severity = COL_RED "Critical"; break;
	case QtFatalMsg:    warn_msg = "FATAL";    severity = COL_RED "Fatal"; break;
	case QtInfoMsg:	    severity = COL_CYAN "Info"; break;
	default:            severity = COL_CYAN "Default"; break;
	}
	console_write(stderr, QString(COL_YELL "%1%2 %3:%5" COL_RESET " %4\n")
			.arg(el/1000, 4)
			.arg((el%1000)/100, 2, 10, QChar('0'))
			.arg(severity).arg(msg)
			.arg(dinfo.log_prefix()).toUtf8());

	if (abort_on_warning == 1 && warn_msg) {
		qFatal("Abort on %s", warn_msg);
	}
}


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

static bool compare_pki_base(pki_base* a, pki_base* b)
{
	return (a->getSqlItemId().toULongLong() <
		b->getSqlItemId().toULongLong());
}

static pki_multi *cmdline_items;
static void read_cmdline(int argc, char *argv[], bool console_only)
{
	arguments cmd_opts(argc, argv);
	pki_evp::passwd = acquire_password(cmd_opts["password"]);
	Passwd sqlpw = acquire_password(cmd_opts["sqlpass"]);

	if (cmd_opts.has("verbose")) {
		QString all = cmd_opts["verbose"];
		debug_info::set_debug(all.isEmpty() ? QString("all") : all);
	}
	if (!cmd_opts.has("password") && console_only)
		database_model::open_without_password = true;

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
			pki_crl *crl = crls->newCrl(task);
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
		cmdline_items = NULL;
	}
}

int main(int argc, char *argv[])
{
	const char *xca_special = getenv("XCA_ARGUMENTS");
	if (xca_special && *xca_special) {
		puts(CCHAR(arguments::doc(xca_special)));
		return 0;
	}
	qInstallMessageHandler(myMessageOutput);
	{
		const char *d = getenv("XCA_DEBUG");
		if (d && *d)
			debug_info::set_debug(QString(d));
	}

#if defined(Q_OS_WIN32)
	// If no style provided externally
	if (!QApplication::style())
		QApplication::setStyle("Fusion");

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
	XcaApplication *gui = nullptr;
	QCoreApplication *coreApp = nullptr;

#if !defined(Q_OS_WIN32)
	if (console_only) {
		coreApp = new QCoreApplication(argc, argv);
	} else
#endif
	{
		/* On windows, always instantiate a GUI app */
		coreApp = gui = new XcaApplication(argc, argv);
		is_gui_app = true;
	}

	coreApp->setApplicationName(PACKAGE_TARNAME);
	coreApp->setOrganizationDomain("de.hohnstaedt");
	coreApp->setApplicationVersion(XCA_VERSION);
	xcaWarning::setGui(new xcaWarningCore());

	migrateOldPaths();

	Entropy entropy;
	Settings.clear();
	try {
		initOIDs();
	} catch (errorEx &e) {
		XCA_ERROR(e);
	}

	for (int i=0; i < argc; i++)
		qDebug() << "wargv" << argc << i << argv[i];
	try {
		if (gui && !console_only) {
			mainwin = new MainWindow();
			gui->setMainwin(mainwin);
			read_cmdline(argc, argv, console_only);
			mainwin->importMulti(cmdline_items, 1);
			cmdline_items = NULL;
			enum open_result r = open_abort;
			if (!Database.isOpen())
				r = mainwin->init_database(QString());
			else
				r = mainwin->setup_open_database();
			qDebug() << "PWret" << r << pw_cancel << pw_ok;
			if (r != pw_exit) {
				mainwin->show();
				gui->exec();
			}
		} else {
			read_cmdline(argc, argv, console_only);
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
	pki_export::free_elements();
#if defined(Q_OS_WIN32)
	FreeConsole();
#endif
	return EXIT_SUCCESS;
}
