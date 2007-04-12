/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CERTDETAIL_H
#define __CERTDETAIL_H

#include "ui_CertDetail.h"

class pki_x509;

class CertDetail: public QDialog, public Ui::CertDetail
{
		Q_OBJECT

	public:
		CertDetail( QWidget *parent);
		void setCert(pki_x509 *cert);
};

#endif
