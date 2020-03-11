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

class XcaProgressBase
{
    public:
	virtual void increment() = 0;
	virtual ~XcaProgressBase() = default;
};

class XcaProgressGui : public XcaProgressBase
{
    private:
	QProgressBar *bar;
	QStatusBar *status;

    public:
	XcaProgressGui() : XcaProgressBase()
	{
		status = mainwin->statusBar();
		bar = new QProgressBar();
		bar->setMinimum(0);
		bar->setMaximum(100);
		bar->setValue(50);

		mainwin->repaint();
		status->addPermanentWidget(bar, 1);
	}
	~XcaProgressGui()
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
};

class XcaProgressCmd : public XcaProgressBase
{
    private:
	int i;

    public:
	XcaProgressCmd() : XcaProgressBase(), i(0)
	{
	}
	~XcaProgressCmd()
	{
		puts(" finished.");
	}
	void increment()
	{
		static const char *spinner = "|/-\\";
		printf("\rGenerating %c ...", spinner[i++%4]);
		fflush(stdout);
	}
};

class XcaProgress
{
    private:
	XcaProgressBase *progress;

    public:
	XcaProgress()
	{
		if (IS_GUI_APP)
			progress = new XcaProgressGui();
		else
			progress = new XcaProgressCmd();
	}
	~XcaProgress()
	{
		delete progress;
	}
	void increment()
	{
		progress->increment();
	}
	static void inc(int, int, void *p)
	{
		XcaProgress *prog = static_cast<XcaProgress*>(p);
		if (prog)
			prog->increment();
	}
};
#endif
