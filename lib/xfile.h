/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2019 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __X_FILE_H
#define __X_FILE_H

#include <QFile>
#include <QDebug>

#include <errno.h>
#include "exception.h"

#include <openssl/bio.h>

class XFile : public QFile
{
	Q_OBJECT

	public:
		bool open(OpenMode flags)
		{
			bool o = QFile::open(flags | Unbuffered);
			if (error()) {
				throw errorEx(tr("Error opening file: '%1': %2")
					.arg(fileName()).arg(strerror(errno)));
			}
			return o;
		}
		XFile(const QString &name) : QFile(name)
		{
		}
		void retry_read()
		{
			seek(0);
			if (error()) {
				throw errorEx(
					tr("Error rewinding file: '%1': %2")
						.arg(fileName())
						.arg(strerror(errno)));
			}
		}
		bool open_key()
		{
			bool o = open_write();
			setPermissions(ReadOwner | WriteOwner);
			return o;
		}
		bool open_write()
		{
			return open(ReadWrite | Truncate);
		}
		bool open_read()
		{
			return open(ReadOnly);
		}
};

#endif
