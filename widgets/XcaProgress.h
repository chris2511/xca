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

#include <QProgressBar>
#include <QStatusBar>

class XcaProgress
{
    private:
	QProgressBar *bar;
	QStatusBar *status;
	int i;

    public:
	XcaProgress()
	{
		if (!IS_GUI_APP) {
			i = 0;
		} else {
			status = mainwin->statusBar();
			bar = new QProgressBar();
			bar->setMinimum(0);
			bar->setMaximum(100);
			bar->setValue(50);

			mainwin->repaint();
			status->addPermanentWidget(bar, 1);
		}
	}
	~XcaProgress()
	{
		if (!IS_GUI_APP) {
			printf(" finished.\n");
		} else {
			status->removeWidget(bar);
			delete bar;
		}
	}
	void increment()
	{
		if (!IS_GUI_APP) {
			static const char *spinner = "|/-\\";
			printf("\rGenerating %c ...", spinner[i%4]);
			fflush(stdout);
			i++;
		} else {
			int value = bar->value();
			if (value == bar->maximum()) {
				bar->reset();
			} else {
				bar->setValue(value +1);
			}
		}
	}
	static void inc(int, int, void *p)
	{
		XcaProgress *prog = static_cast<XcaProgress*>(p);
		prog->increment();
	}
};
#endif
