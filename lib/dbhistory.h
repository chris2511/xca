/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DBHISTORY_H
#define __DBHISTORY_H
#include <QStringList>
#include <QString>

class dbhistory
{
	private:
		QStringList history{};
		static QString lastRemote;

	public:
		dbhistory();
		void addEntry(const QString &name);
		QStringList get() const
		{
			return history;
		}
		static void setLastRemote(const QString &db);
		static QString getLastRemote();
};
#endif
