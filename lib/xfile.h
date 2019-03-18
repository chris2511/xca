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
#include <stdio.h>
#include <unistd.h>
#include "exception.h"

class XFile : public QFile
{
	private:
		FILE *filp;
		bool _open(QIODevice::OpenMode flags)
		{
			bool o = open(flags);
			if (error()) {
				throw errorEx(tr("Error opening file: '%1': %2")
					.arg(fileName()).arg(strerror(errno)));
			}
			return o;
		}
	public:
		XFile(const QString &name) : QFile(name)
		{
			filp = NULL;
		}
		FILE *fp()
		{
			if (filp) {
				fseek(filp, 0, SEEK_END);
			} else {
				filp = fdopen(dup(handle()),
					openMode() & QIODevice::WriteOnly ?
						"ab" : "rb");
				check_oom(filp);
			}
			return filp;
		}
		qint64 writeData(const char *data, qint64 maxSize)
		{
			if (filp)
				fflush(filp);
			flush();
			seek(size());
			qint64 r = QFile::writeData(data, maxSize);
			flush();
			return r;
		}
		void retry_read()
		{
			seek(0);
			if (filp)
				fseek(filp, 0, SEEK_SET);
			if (error()) {
				throw errorEx(
					tr("Error rewinding file: '%1': %2")
						.arg(fileName())
						.arg(strerror(errno)));
			}
		}
		bool open_key()
		{
			mode_t m = umask(077);
			bool o = open_write();
			umask(m);
			return o;
		}
		bool open_write()
		{
			return _open(QIODevice::ReadWrite|QIODevice::Truncate);
		}
		bool open_read()
		{
			return _open(QIODevice::ReadOnly);
		}

		~XFile() {
			if (filp)
				fclose(filp);
		}
};

#endif
