/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2019 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "CrlTreeView.h"
#include "lib/db_crl.h"
#include "lib/database_model.h"

CrlTreeView::CrlTreeView(QWidget *parent)
	: XcaTreeView(parent)
{
}

void CrlTreeView::setModels(database_model *models)
{
	db_crl *crls = models->model<db_crl>();
	XcaTreeView::setModel(crls);
}
