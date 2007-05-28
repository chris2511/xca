/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ReqDetail.h"
#include "MainWindow.h"
#include "distname.h"
#include "clicklabel.h"
#include "lib/pki_x509req.h"
#include "lib/func.h"
#include <qlabel.h>
#include <qlineedit.h>

ReqDetail::ReqDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::csrImg);
	descr->setReadOnly(true);
}

void ReqDetail::setReq(pki_x509req *req)
{
	// internal name and verification
	descr->setText(req->getIntName());
	if (!req->verify() ) {
		verify->setRed();
		verify->setText("Failed");
	}
	else {
		verify->setGreen();
		if (req->isSpki()) {
			verify->setText("SPKAC");
		}
		else {
			verify->setText("PKCS#10");
		}
	}
	verify->disableToolTip();
	// look for the private key
	pki_key *key =req->getRefKey();
	if (key) {
		privKey->setText(key->getIntName());
		privKey->setGreen();
	}
	else {
		privKey->setText(tr("Not available"));
		privKey->setDisabled(true);
		privKey->disableToolTip();
	}
	// the subject
	subject->setX509name(req->getSubject());

	// Algorithm
	sigAlgo->setText(req->getSigAlg());

	// The extensions
	extList el = req->getV3Ext();
	if (el.count() == 0) {
		tabwidget->removeTab(3);
	} else {
		v3extensions->document()->setHtml(el.getHtml("<br>"));
	}

	// The non extension attributes
	int cnt = X509_REQ_get_attr_count(req->getReq());
	int added = 0;
	QGridLayout *attrLayout = new QGridLayout(attributes);
	attrLayout->setAlignment(Qt::AlignTop);
	attrLayout->setSpacing(6);
	attrLayout->setMargin(11);

	for (int i = 0; i<cnt; i++) {
		int nid;
		QLabel *label;
		X509_ATTRIBUTE *att = X509_REQ_get_attr(req->getReq(), i);
		nid = OBJ_obj2nid(att->object);
		if (X509_REQ_extension_nid(nid)) {
			continue;
		}
		label = new QLabel(this);
		label->setText(QString(OBJ_nid2ln(nid)));
		label->setToolTip(QString(OBJ_nid2sn(nid)));
		attrLayout->addWidget(label, i, 0);
		added++;

		if (att->single) {
			label = labelFromAsn1Type(att->value.single);
			attrLayout->addWidget(label, i, 1);
			continue;
		}
		int count = sk_ASN1_TYPE_num(att->value.set);
		for (int j=0; j<count; j++) {
			label = labelFromAsn1Type(sk_ASN1_TYPE_value(att->value.set, j));
			attrLayout->addWidget(label, i, j +1);
		}
	}
	if (!added) {
		tabwidget->removeTab(2);
	}
}

QLabel *ReqDetail::labelFromAsn1Type(ASN1_TYPE *at)
{
	QLabel *label;
	ASN1_STRING *st = at->value.asn1_string;

	label = new CopyLabel(this);
	label->setText(asn1ToQString(st));
	label->setToolTip(QString(ASN1_tag2str(st->type)));
	label->setFrameShape(QFrame::Panel);
	label->setFrameShadow(QFrame::Sunken);
	return label;
}
