/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PWDIALOGMOCK_H
#define __PWDIALOGMOCK_H
#include <QDebug>

#include "lib/debug_info.h"
#include "lib/PwDialogCore.h"

class pw_expect
{
  public:
	bool write;
	bool abort;
	pass_info pi;

	Passwd pass_return;
	enum open_result result;

	pw_expect(const char *p, enum open_result r) :
		write(false), abort(false), pi(QString(), QString()),
		pass_return(), result(r)
	{
		pass_return = p;
	}
};

class PwDialogMock: public PwDialogUI_i
{
    enum open_result execute(pass_info *p, Passwd *passwd,
					bool write = false, bool abort = false)
	{
		if (pw_expectations.size() <= expect_idx)
			return open_abort;

		pw_expect *pwe = pw_expectations[expect_idx++];
		pwe->write = write;
		pwe->abort = abort;
		pwe->pi.setTitle(p->getTitle());
		pwe->pi.setDescription(p->getDescription());

		qWarning() << "PwDialogMock" << p->getDescription() << expect_idx
					<< "Password:" << pwe->pass_return;
		*passwd = pwe->pass_return;
		return pwe->result;
	}

	~PwDialogMock()
	{
		qDeleteAll(pw_expectations);
	}

	public:

	int expect_idx{};
	QList<pw_expect*> pw_expectations{};

	void setExpectations(const QList<pw_expect*> pwe)
	{
		qDeleteAll(pw_expectations);
		pw_expectations = pwe;
		expect_idx = 0;
	}
};
#endif
