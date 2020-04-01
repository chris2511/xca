/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __SETTINGS_H
#define __SETTINGS_H

#include <QString>
#include <QStringList>
#include <QMap>
#include <Qt>

class settings;
class svalue
{
    private:
	settings *setting;
	QString key;
	QString get() const;
	void set(const QString &val);

    public:
	svalue(settings *s, const QString &k);
	QStringList split(QString sep)
	{
		return get().split(sep);
	}
	bool empty()
	{
		return get().isEmpty();
	}
	const QString &operator = (const QString &val)
	{
		set(val);
		return val;
	}
	int operator = (int val)
	{
		set(QString("%1").arg(val));
		return val;
	}
	unsigned operator = (unsigned val)
	{
		set(QString("%1").arg(val));
		return val;
	}
	bool operator = (bool val)
	{
		set(QString(val ? "yes" : "no"));
		return val;
	}
	enum Qt::CheckState operator = (enum Qt::CheckState val)
	{
		set(QString(val == Qt::Checked ? "yes" : "no"));
		return val;
	}
	operator QString()
	{
		return get();
	}
	operator int()
	{
		return get().toInt();
	}
	operator unsigned()
	{
		return get().toUInt();
	}
	operator bool()
	{
		return get() == "yes";
	}
	operator enum Qt::CheckState()
	{
		return get() == "yes" ? Qt::Checked : Qt::Unchecked;
	}
	QString operator +(const QString &other)
	{
		return get() + other;
	}
	QString operator +(const char *other)
	{
		return get() + other;
	}
};

class settings
{
	friend class svalue;

    private:
	bool loaded;
	QStringList db_keys, hostspecific;
	QMap<QString, QString> values;
	QMap<QString, QString> defaul;
	void load_settings();
	QString get(QString key);
	void set(QString key, QString value);
	void setAction(const QString &key, const QString &value);

    public:
	settings();
	void clear();
	QString defaults(const QString &key);

	svalue operator[] (QString x)
	{
		return svalue(this, x);
	}
};

extern settings Settings;
#endif
