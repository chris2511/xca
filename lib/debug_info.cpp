/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QStringList>
#include <QDebug>
#include <QElapsedTimer>
#include <stdlib.h>

#include "debug_info.h"
#include "base.h"
#include "func.h"

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
						unsigned line) const
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

static void myMessageOutput(QtMsgType type, const QMessageLogContext &ctx,
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

void debug_info::init()
{
	qInstallMessageHandler(myMessageOutput);
	const char *d = getenv("XCA_DEBUG");
	if (d && *d)
		debug_info::set_debug(QString(d));
}
