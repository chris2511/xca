/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QList>
#include <QDebug>

#include "func.h"
#include "exception.h"
#include "arguments.h"

#include <getopt.h>
#include <stdio.h>

#if !defined(Q_OS_WIN32)
#include <sys/ioctl.h>
#endif


const QList<arg_option> arguments::opts = {
	arg_option("crlgen", "ca-identifier", required_argument, true, true,
		"Generate CRL for <ca>. Use the 'name' option to set the internal name of the new CRL."),
	arg_option("database", "database", file_argument, false, false,
		"File name (*.xdb) of the SQLite database or a remote database descriptor: [user@host/TYPE:dbname#prefix]."),
	arg_option("exit", NULL, no_argument, false, false,
		"Exit after importing items."),
	arg_option("help", NULL, no_argument, true, false,
		"Print this help and exit."),
	arg_option("hierarchy", "directory", file_argument, true, true,
		"Save OpenSSL index hierarchy in <dir>."),
	arg_option("index", "file", file_argument, true, true,
		"Save OpenSSL index in <file>."),
	arg_option("import", NULL, no_argument, false, true,
		"Import all provided items into the database."),
	arg_option("issuers", NULL, no_argument, true, true,
		"Print all known issuer certificates that have an associated private key and the CA basic constraints set to 'true'."),
	arg_option("keygen", "type", required_argument, true, true,
		"Generate a new key and import it into the database. Use the 'name' option to set the internal name of the new key. The <type> parameter has the format: '[RSA|DSA|EC]:[<size>|<curve>]."),
	arg_option("list-curves", NULL, no_argument, true, false,
		"Prints all known Elliptic Curves."),
	arg_option("name", "internal-name", required_argument, false, true,
		"Provides the name of new generated items. An automatic name will be generated if omitted."),
	arg_option("no-gui", NULL, no_argument, true, false,
		"Do not start the GUI. Alternatively set environment variable XCA_NO_GUI=1 or call xca as 'xca-console' symlink."),
	arg_option("password", "password", required_argument, false, false,
		"Database password for unlocking the database."),
	arg_option("pem", NULL, no_argument, true, false,
		"Print PEM representation of provided files. Prints only the public part of private keys."),
	arg_option("print", NULL, no_argument, true, false,
		"Print a synopsis of provided files."),
	arg_option("sqlpass", "password", required_argument, false, false,
		"Password to access the remote SQL server."),
	arg_option("text", NULL, no_argument, true, false,
		"Print the content of provided files as OpenSSL does."),
	arg_option("verbose", NULL, no_argument, false, false,
		"Print debug log on stderr. Alternatively set the environment variable XCA_DEBUG=1."),
	arg_option("version", NULL, no_argument, true, false,
		"Print version information and exit."),
};

static QMap<QString, QString> getPassDoc()
{
	QMap<QString, QString> passdoc;
	passdoc["pass:password"] = "The actual password is password. Since the password is visible to utilities (like 'ps' under Unix) this form should only be used where security is not important.";
	passdoc["env:var"] = "Obtain the password from the environment variable var. Since the environment of other processes is visible on certain platforms (e.g. ps under certain Unix OSes) this option should be used with caution.";
	passdoc["file:pathname"] = "The first line of pathname is the password. If the same pathname argument is supplied to password and sqlpassword arguments then the first line will be used for both passwords. pathname need not refer to a regular file: it could for example refer to a device or named pipe.";
	passdoc["fd:number"] = "Read the password from the file descriptor number. This can be used to send the data via a pipe for example.";
	passdoc["stdin"] = "Read the password from standard input.";

	return passdoc;
}

arg_option::arg_option(const char *l, const char *a, int has,
			bool n, bool nd, const char *h)
	: long_opt(l), arg(a), arg_type(has), no_gui(n), need_db(nd), help(h)
{
}

void arg_option::fillOption(struct option *opt) const
{
	opt->name = long_opt;
	opt->has_arg = arg_type;
	if (arg_type == file_argument)
		opt->has_arg = required_argument;
	opt->flag = NULL;
	opt->val = 0;
}

static QString splitQstring(int offset, int width, const QString &text)
{
	QStringList lines;
	QString line;

	foreach(const QString &word, text.split(" ")) {
		if (line.size() + word.size() < width - offset) {
			line += " " + word;
			continue;
		}
		lines += line;
		line = word;
	}
	lines += line;
	return lines.join(QString("\n") +QString().fill(' ', offset));
}

QString arguments::man()
{
	QString s;
	QMap<QString, QString> passdoc = getPassDoc();

	for (auto i = opts.begin(); i != opts.end(); ++i) {
		QString longopt = i->long_opt;
		if (i->arg)
			longopt += QString("=<%1>").arg(i->arg);
		s += QString(".TP\n.B \\-\\-%1%3\n%2\n")
			.arg(longopt)
			.arg(i->help)
			.arg(i->need_db ? " *" : "");
	}
	s += ".br\n.TP\n"
"Options marked with an asterisk need a database. Either from the commandline or as default database.\n"
"\n.SH PASS PHRASE ARGUMENTS\n"
"The password options accept the same syntax as openssl does:\n";
	foreach(QString key, passdoc.keys())
		s += QString(".TP\n.B %1\n%2\n").arg(key).arg(passdoc[key]);
	return s;
}

static QString esc(QString msg)
{
	return msg.replace(QRegExp("([\\*@:'_])"), "\\\\1");
}

QString arguments::rst()
{
	QString s = "..\n"
"  Automatically created by\n"
"  XCA_SPECIAL=rst ./xca > doc/rst/arguments.rst\n\n";

	QMap<QString, QString> passdoc = getPassDoc();
	int space = (maxOptWidth() + 4) * -1;

	for (auto i = opts.begin(); i != opts.end(); ++i) {
		QString longopt = i->long_opt;
		if (i->arg)
			longopt += QString("=%1").arg(esc(i->arg));
		s += QString("--%1 %2%3\n")
			.arg(esc(longopt), space)
			.arg(esc(i->help))
			.arg(i->need_db ? " [#need-db]_" : "");
	}
	s += "\n\n"
".. [#need-db] Requires a database. Either from the commandline or as default database.\n\n"
"Passphrase arguments\n"
".....................\n"
"The password options accept the same syntax as openssl does:\n\n";
	foreach(QString key, passdoc.keys())
		s += QString("%1\n  %2\n").arg(esc(key)).arg(esc(passdoc[key]));
	return s;
}

QString arguments::completion()
{
	QStringList sl;
	for (auto i = opts.begin(); i != opts.end(); ++i)
		sl << QString("--%1").arg(i->long_opt);
	return sl.join(" ");
}

QString arguments::doc(const QString &which)
{
	if (which == "rst")
		return rst();
	if (which == "man")
		return man();
	if (which == "completion")
		return completion();
	return QString();
}

size_t arguments::maxOptWidth()
{
	size_t len = 0;
	foreach(const arg_option &a, opts) {
		size_t l = strlen(a.long_opt);
		if (a.arg)
			l += strlen(a.arg);
		if (l > len)
			len = l;
	}
	return len;
}

QString arguments::help()
{
	QString s;
	size_t len;
	int width = 80, offset;
#if !defined(Q_OS_WIN32)
	struct winsize w;

	ioctl(0, TIOCGWINSZ, &w);
	if (w.ws_col > 20)
		width = w.ws_col;
#endif
	QMap<QString, QString> passdoc = getPassDoc();

	len = maxOptWidth() +4;
	offset = len + 7;
	for (auto i = opts.begin(); i != opts.end(); ++i) {
		QString longopt = i->long_opt;
		if (i->arg)
			longopt += QString("=<%1>").arg(i->arg);
		QString help = splitQstring(offset, width, i->help);
		s += QString(" " COL_CYAN "%3 " COL_RESET
				 COL_BOLD "--%1" COL_RESET " %2\n")
			.arg(longopt, len*-1)
			.arg(help)
			.arg(i->need_db ? "*" : " ");
	}
	s += "\n[" COL_CYAN "*" COL_RESET "]" + splitQstring(sizeof("[*] ") -1, width,
	     QString("Needs a database. Either from the commandline or as default database")) + "\n";
	s += "\n" + splitQstring(0, width, QString("The password options accept the same syntax as openssl does:\n"));
	foreach(QString key, passdoc.keys())
		s += QString("\n   " COL_BOLD "%1" COL_RESET).arg(key, -14) +
			splitQstring(18, width, passdoc[key]);
	return s;
}

int arguments::parse(int argc, char *argv[])
{
	int i, cnt = opts.count();

	/* Setup "struct option" */
	if (!long_opts)
		long_opts = new struct option[cnt+1];

	check_oom(long_opts);
	for (i = 0; i < cnt; ++i)
		opts[i].fillOption(long_opts +i);
	long_opts[cnt].name = NULL;
	long_opts[cnt].flag = NULL;
	opterr = 0;
	/* Parse cmdline options argv */
	while (true) {
		int optind = 0;
		result = getopt_long_only(argc, argv, ":", long_opts, &optind);
		if (result)
			break;
		const arg_option i = opts[optind];
		found_options[i.long_opt] = QString::fromUtf8(optarg);
		if (i.need_db)
			need_db = true;
	}
	for (i = optind; i < argc; ++i) {
		QString file = QString::fromUtf8(argv[i]);
		if (!has("database") && file.endsWith(".xdb")) {
			/* No database given, but here is an xdb file
			 * Try to be clever.
			 */
			found_options["database"] = file;
		} else {
			files << file;
		}
	}
	if (result == ':') {
		result_string = QString("Missing option argument for '%1'")
					.arg(argv[optind-1]);
	}
	if (result == '?') {
		result_string = QString("Invalid option: '%1'")
					.arg(argv[optind-1]);
	}
	if (result == -1)
		result = 0;

	return result;
}

QString arguments::resultString() const
{
	return result_string;
}

arguments::arguments(int argc, char *argv[])
{
	long_opts = NULL;
	need_db = false;
	parse(argc, argv);
}

arguments::arguments(const arguments &a)
{
	*this = a;
}

arguments &arguments::operator = (const arguments &a)
{
	long_opts = NULL;
	files = a.files;
	found_options = a.found_options;
	return *this;
}

arguments::~arguments()
{
	delete long_opts;
}

QString arguments::operator [] (const QString &key) const
{
	return found_options[key];
}

bool arguments::has(const QString &opt) const
{
	return found_options.contains(opt);
}

QStringList arguments::getFiles() const
{
	return files;
}

int arguments::getResult() const
{
	return result;
}

bool arguments::needDb() const
{
	return need_db;
}

bool arguments::is_console(int argc, char *argv[])
{
	const char *nogui = getenv("XCA_NO_GUI");
	if (nogui && *nogui)
		return true;
	if (argc > 0 && QString(argv[0]).endsWith("xca-console"))
		return true;

	/* Setup "no-gui" options */
	QStringList console_opts;
	for (auto i = opts.begin(); i != opts.end(); ++i) {
		if (i->no_gui)
			console_opts << QString("-%1").arg(i->long_opt);
	}

	qDebug() << "NOGUI_OPTS" << console_opts;
	for (int i = 1; i < argc; i++) {
		QString arg = QString(argv[i]);
		if (arg.startsWith("--"))
			arg = arg.mid(1);
		foreach(QString opt, console_opts) {
			if (opt.startsWith(arg))
				return true;
		}
	}
	return false;
}
