/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCADETAIL_H
#define __XCADETAIL_H

#include <QDialog>

class pki_base;
class ImportMulti;

class XcaDetail: public QDialog
{
	Q_OBJECT

	protected:
		pki_base *pki{};
		ImportMulti *importmulti{};
		QPushButton *importbut{};
		void updateNameComment();

	public:
		XcaDetail(QWidget *w);
		void init(const char *help, const char *img);
		void connect_pki(pki_base *p);

	public slots:
		void accept();
		void import();
		virtual void itemChanged(pki_base*);
};
#endif
