/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __KEYDETAIL_H
#define __KEYDETAIL_H

#include "ui_KeyDetail.h"
#include "XcaDetail.h"

class pki_key;
class pki_base;

class KeyDetail: public XcaDetail, public Ui::KeyDetail
{
	Q_OBJECT

	QVariant keySqlId{};

  public:
	KeyDetail(QWidget *w = nullptr);
	void setKey(pki_key *key, bool import = true);
	void setupFingerprints(pki_key *key);
	static void showKey(QWidget *parent, pki_key *key, bool import = true);

  public slots:
	void itemChanged(pki_base *pki) override;
};
#endif
