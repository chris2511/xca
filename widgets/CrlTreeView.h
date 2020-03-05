/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CRLTREEVIEW_H
#define __CRLTREEVIEW_H

#include "XcaTreeView.h"

class CrlTreeView: public XcaTreeView
{
	Q_OBJECT

    public:
	CrlTreeView(QWidget *parent) : XcaTreeView(parent) { }
	void showPki(pki_base *pki) const;
};
#endif
