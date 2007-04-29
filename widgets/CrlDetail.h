/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CRLDETAIL_H
#define __CRLDETAIL_H

#include "ui_CrlDetail.h"

class pki_crl;
class MainWindow;

class CrlDetail: public QDialog, public Ui::CrlDetail
{
	Q_OBJECT
	private:
		MainWindow *mw;
	public:
		CrlDetail(MainWindow *mainwin);
		void setCrl(pki_crl *crl);
};
#endif
