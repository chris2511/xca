/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CRLTREEVIEW_H
#define __CRLTREEVIEW_H

#include "XcaTreeView.h"
#include "lib/database_model.h"

class CrlTreeView: public XcaTreeView
{
	Q_OBJECT

    public:
	CrlTreeView(QWidget *parent);
	void setModels(database_model *models);
};
#endif
