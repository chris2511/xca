/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __ARGUMENTS_H
#define __ARGUMENTS_H

#include <getopt.h>

#include <QString>
#include <QStringList>
#include <QMap>

#include "func.h"

struct option;

#define file_argument (required_argument+1)
class arg_option
{
    public:
	const char *long_opt;
	const char *arg;
	int arg_type;
	bool no_gui;
	bool need_db;
	QString help;

	arg_option(const char *l, const char *a, int has_arg,
		bool n, bool nd, const char *h);
	void fillOption(struct option *opt) const;
};

class arguments
{
    private:
	static const QList<arg_option> opts;
	int result;
	QMap<QString, QString> found_options;
	QStringList files;
	struct option *long_opts;
	bool need_db;
	QString result_string;

    public:
	static bool is_console(int argc, char *argv[]);
	static QString help();
	static QString man();
	static QString rst();
	static QString completion();
	static size_t maxOptWidth();
	static QString doc(const QString &which);

	arguments(int argc, char *argv[]);
	arguments(const arguments &a);
	~arguments();

	QString operator [] (const QString &) const;
	arguments &operator = (const arguments &);
	bool has(const QString &opt) const;
	int parse(int argc, char *argv[]);
	QStringList getFiles() const;
	int getResult() const;
	QString resultString() const;
	bool needDb() const;
};
#endif
