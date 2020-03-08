/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAPROGRESS_H
#define __XCAPROGRESS_H

#include "lib/base.h"
#include "lib/main.h"
#include "widgets/MainWindow.h"

#include <QMessageBox>
#include <QProgressBar>
#include <QStatusBar>
#include <QContextMenuEvent>

class XcaProgress
{
    private:
	QProgressBar *bar;
	QStatusBar *status;

    public:
	XcaProgress()
	{
		status = mainwin->statusBar();
		bar = new QProgressBar();
		bar->setMinimum(0);
		bar->setMaximum(100);
		bar->setValue(50);

		mainwin->repaint();
		status->addPermanentWidget(bar, 1);
	}
	~XcaProgress()
	{
		status->removeWidget(bar);
		delete bar;
	}
	void increment()
	{
		int value = bar->value();
		if (value == bar->maximum()) {
			bar->reset();
		} else {
			bar->setValue(value +1);
		}
	}
	static void inc(int, int, void *p)
	{
		XcaProgress *prog = static_cast<XcaProgress*>(p);
		prog->increment();
	}
};
#endif
