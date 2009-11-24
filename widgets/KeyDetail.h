/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __KEYDETAIL_H
#define __KEYDETAIL_H

#include "ui_KeyDetail.h"

class pki_key;

class KeyDetail: public QDialog, private Ui::KeyDetail
{
	Q_OBJECT

   public:
	KeyDetail(QWidget *parent);
	void setKey(pki_key *key);

};
#endif
