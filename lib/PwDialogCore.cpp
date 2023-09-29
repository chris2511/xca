/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/func.h"
#include "lib/base.h"
#include "lib/Passwd.h"
#include "lib/exception.h"
#include "XcaWarningCore.h"
#include "PwDialogCore.h"
#include <QLabel>
#include <QMessageBox>

PwDialogUI_i *PwDialogCore::pwdialog;
Passwd PwDialogCore::cmdline_passwd;

enum open_result PwDialogCore::execute(pass_info *p, Passwd *passwd,
					bool write, bool abort)
{
	if (!cmdline_passwd.isEmpty()) {
		*passwd = cmdline_passwd;
		cmdline_passwd.cleanse();
		return pw_ok;
	}
	if (pwdialog)
		return pwdialog->execute(p, passwd, write, abort);
#if !defined(Q_OS_WIN32)
	console_write(stdout, QString(COL_CYAN "%1\n" COL_LRED "%2:" COL_RESET)
				.arg(p->getDescription())
				.arg(QObject::tr("Password")).toUtf8());
	*passwd = readPass();
	return pw_ok;
#else
	throw pw_exit;
#endif
}

int PwDialogCore::pwCallback(char *buf, int size, int rwflag, void *userdata)
{
	Passwd passwd;
	enum open_result result;
	pass_info *p = static_cast<pass_info *>(userdata);

	result = execute(p, &passwd, rwflag, false);

	size = MIN(size, passwd.size());
	memcpy(buf, passwd.constData(), size);
	p->setResult(result);
	return result == pw_ok ? size : 0;
}

void PwDialogCore::setGui(PwDialogUI_i *p)
{
	delete pwdialog;
	pwdialog = p;
}
