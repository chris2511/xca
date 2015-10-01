/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __OID_RESOLVER_H
#define __OID_RESOLVER_H

#include "ui_OidResolver.h"

class OidResolver: public QWidget, public Ui::OidResolver
{
	Q_OBJECT

   public:
	OidResolver(QWidget *w);

   public slots:
	void searchOid(QString s);

};
#endif
