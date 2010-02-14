/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_EXCEPTION_H
#define PKI_EXCEPTION_H

#include <qstring.h>
#include <qobject.h>
#include "base.h"

class errorEx
{
	private:
		QString msg;
	public:
		errorEx(QString txt, QString className = "")
		{
			msg = txt;
			if (!className.isEmpty())
				msg += " (" + className + ")";
		}
		errorEx(const errorEx &e)
		{
			msg = e.msg;
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
			return msg.toAscii();
		}
		bool isEmpty() const
		{
			return msg.isEmpty();
		}
};

#define check_oom(ptr) if(!ptr){throw errorEx(QObject::tr("Out of Memory"));}
#endif
