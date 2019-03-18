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
#include <errno.h>
#include "exception.h"

class XFile : public QFile
{
	private:
		FILE *filp;

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
			filp = NULL;
		}
		FILE *fp(const char *mode = NULL)
		{
			if (!filp) {
				if (!mode)
					mode = openMode() & WriteOnly ?
							"ab" : "rb";
				filp = fdopen(dup(handle()), mode);
				check_oom(filp);
			}
			qDebug() << fileName() << "FILE ptr @" << ftell(filp);
			return filp;
		}
		qint64 writeData(const char *data, qint64 maxSize)
		{
			if (filp)
				fflush(filp);
			flush();
			seek(size());
			qDebug() << "WriteData to" << fileName() <<
					maxSize << "@" << size();
			qint64 r = QFile::writeData(data, maxSize);
			flush();
			if (filp)
				fseek(filp, 0, SEEK_END);
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
			return open(ReadWrite | Truncate);
		}
		bool open_read()
		{
			return open(ReadOnly);
		}

		~XFile() {
			if (filp)
				fclose(filp);
		}
};

#endif
