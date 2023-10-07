/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DHGEN_H
#define __DHGEN_H

#include "exception.h"

#include <QString>
#include <QThread>

class DHgen: public QThread
{
	QString fname{};
	int bits{};
	errorEx err{};

  public:
	DHgen(const QString &n, int b) : QThread(), fname(n), bits(b) {}
	QString filename() const { return fname; }
	errorEx error() const { return err; }

  protected:
	void run();
};
#endif
