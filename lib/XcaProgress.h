/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAPROGRESS_H
#define __XCAPROGRESS_H

#include <QString>

class XcaProgress_i
{
  public:
	XcaProgress_i() = default;
	virtual void start(const QString &what, int max) = 0;
	virtual void stop() = 0;
	virtual void increment() = 0;
	virtual ~XcaProgress_i() = default;
};

class XcaProgressCmd : public XcaProgress_i
{
  private:
	int i{};

  public:
	void start(const QString &what, int max);
	void stop();
	void increment();
};

class XcaProgress
{
  private:
	static XcaProgress_i *progress;

  public:
	XcaProgress(const QString &what = QString(), int max = 100);
	~XcaProgress();
	void increment();

	static void inc(int, int, void *p);
	static void setGui(XcaProgress_i *p);
};
#endif
