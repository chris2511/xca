/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_TOKEN_H
#define __DB_TOKEN_H

#include <QtCore/QObject>
#include <QtGui/QPixmap>
#include <QtCore/QEvent>

#include "db_base.h"

class db_token: public db_base
{
		Q_OBJECT
	private:
		unsigned long slot;
	public:
		db_token(QString db, MainWindow *mw);
		bool setData(const QModelIndex &index,
			const QVariant &value, int role);
		void setSlot(unsigned long s)
		{
			slot = s;
		}
};

#endif
