/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <openssl/objects.h>
#include "OidResolver.h"
#include "lib/base.h"
#include "lib/func.h"
#include "lib/exception.h"

OidResolver::OidResolver(QWidget *parent)
	:QWidget(parent)
{
	setWindowTitle(tr(XCA_TITLE));
	setupUi(this);
}

void OidResolver::searchOid(QString s)
{
	bool ok;
	int n;

	input->setText(s);
	s = s.trimmed();
	n = s.toUInt(&ok);
	if (!ok)
		n = OBJ_txt2nid(CCHAR(s));
	ign_openssl_error();
	if (n == NID_undef) {
		ln->clear();
		sn->clear();
		oid->clear();
		nid->clear();
	} else {
		const ASN1_OBJECT *a = OBJ_nid2obj(n);
		ln->setText(OBJ_nid2ln(n));
		sn->setText(OBJ_nid2sn(n));
		nid->setText(QString("%1").arg(n));
		if (a) {
			try {
				oid->setText(OBJ_obj2QString(a, 1));
			} catch (errorEx &e) {
				oid->clear();
			}
		} else {
			oid->clear();
		}
	}
	ign_openssl_error();
	show();
	raise();
}
