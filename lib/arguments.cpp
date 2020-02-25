/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <getopt.h>
#include <sys/ioctl.h>
#include <stdio.h>

#include "arguments.h"

#include <QList>
#include <QDebug>

#include "func.h"
#include "exception.h"

const QList<arg_option> arguments::opts = {
	arg_option("database",  "<database>", file_argument, false, false,
		"File name (*.xdb) of the SQLite database or a remote database descriptor: [user@host/TYPE:dbname#prefix]"),
	arg_option("exit",      NULL, no_argument, false, false,
		"Exit after importing items"),
	arg_option("gencrl",    "<ca identifier>", required_argument, true, true,
		"Generate CRL for <ca>"),
	arg_option("help",      NULL, no_argument, true, false,
		"Print this help and exit"),
	arg_option("hierarchy",  "<dir>", file_argument, true, true,
		"Save OpenSSL index hierarchy in <dir>"),
	arg_option("index",     "<file>", file_argument, true, true,
		"Save OpenSSL index in <file>"),
	arg_option("no-gui",    NULL, no_argument, true, false,
		"Do not start the GUI. Alternatively set environment variable XCA_NO_GUI=1 or call xca as 'xca-console' symlink"),
	arg_option("password",  "<password>", required_argument, false, false,
		"Database password for unlocking the database"),
	arg_option("print",     NULL, no_argument, true, false,
		"Print a synopsis of provided files"),
	arg_option("sqlpass",  "<password>", required_argument, false, false,
		"Password to access the remote SQL server"),
	arg_option("text",      NULL, no_argument, true, false,
		"Print the content of provided files as OpenSSL does."),
	arg_option("verbose",   NULL, no_argument, false, false,
		"Print debug log on stderr. Alternatively set the environment variable XCA_DEBUG=1"),
	arg_option("version",   NULL, no_argument, true, false,
		"Print version information and exit"),
};

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
		line.clear();
	}
	lines += line;
	return lines.join(QString("\n") +QString().fill(' ', offset));
}

QString arguments::help()
{
	QString s;
	size_t len = 0;
	int width = 80, offset;
	struct winsize w;

	ioctl(0, TIOCGWINSZ, &w);
	if (w.ws_col > 20)
		width = w.ws_col;

	foreach(const arg_option &a, opts) {
		size_t l = strlen(a.long_opt) + 1;
		if (a.arg)
			l += strlen(a.arg) + 1;
		if (l > len)
			len = l;
	}
	offset = len + 5;
	for (auto i = opts.begin(); i != opts.end(); ++i) {
		QString longopt = i->long_opt;
		if (i->arg)
			longopt += QString("=%1").arg(i->arg);
		QString help = splitQstring(offset, width, i->help);
		s += QString("  --%1 %2%3\n")
			.arg(longopt, len*-1).arg(help)
			.arg(i->need_db ? " [*]" : "");
	}
	s += "\n"
	     " [*] Needs a database. Either from the commandline\n"
	     "     or as default database\n";
	return s;
}

int arguments::parse(int argc, char *argv[])
{
	int i, cnt = opts.count();

	/* Setup "struct option" */
	if (!long_opts)
		long_opts = (struct option*)calloc(cnt +1,
							sizeof(*long_opts));
	check_oom(long_opts);
	for (i = 0; i < cnt; ++i)
		opts[i].fillOption(long_opts +i);

	/* Parse cmdline options argv */
	while (true) {
		int optind = 0;
		result = getopt_long_only(argc, argv, "", long_opts, &optind);
		if (result)
			break;
		const arg_option i = opts[optind];
		found_options[i.long_opt] = i.arg_type == file_argument ?
			filename2QString(optarg) : QString(optarg);
		if (i.need_db)
			need_db = true;
	}
	for (i = optind; i < argc; ++i) {
		QString file = filename2QString(argv[i]);
		if (!has("database") && file.endsWith(".xdb")) {
			/* No database given, but here is an xdb file
			 * Try to be clever.
			 */
			found_options["database"] = file;
		} else {
			files << file;
		}
	}
	return result;
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
	if (long_opts)
		free(long_opts);
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
		if (console_opts.contains(arg))
			return true;
	}
	return false;
}
