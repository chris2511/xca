/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DEBUG_INFO_H
#define __DEBUG_INFO_H

#include <QString>
#include <QList>

class dbg_pattern
{
		QString file, func;
		unsigned first, last;
		bool inv;
	public:
		bool invert() const { return inv; }
		dbg_pattern(QString);
		bool match(const QString &curr_file, const QString &curr_func,
					unsigned line) const;
};

class debug_info
{
	private:
		QString short_file;
		QString short_func;
		unsigned line;

		static QList<dbg_pattern> patternlist;
	public:
		static bool all;
		static void set_debug(const QString &dbg);
		static void init();
		debug_info(const QMessageLogContext &c);
		QString log_prefix() const;
		bool do_debug() const;
		static bool isEmpty()
		{
			return patternlist.size() == 0;
		}
};

#endif
