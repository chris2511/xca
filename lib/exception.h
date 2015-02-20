/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_EXCEPTION_H
#define __PKI_EXCEPTION_H

#include <QString>
#include <QObject>
#include "base.h"

#define E_PASSWD 1

class errorEx
{
	private:
		QString msg;
	public:
		int info;
		errorEx(QString txt = "", QString className = "", int inf = 0)
		{
			msg = txt;
			if (!className.isEmpty())
				msg += " (" + className + ")";
			info = inf;
		}
		errorEx(const errorEx &e)
		{
			msg = e.msg;
			info = e.info;
		}
		void appendString(QString s)
		{
			msg = msg + " " + s;
		}
		QString getString() const
		{
			return msg;
		}
		const char *getCString() const
		{
			return msg.toLatin1();
		}
		bool isEmpty() const
		{
			return msg.isEmpty();
		}
};

#define check_oom(ptr) \
	if(!ptr) { \
		throw errorEx(QObject::tr("Out of Memory at %1:%2").\
			arg(C_FILE).arg(__LINE__)); \
	}

#endif
