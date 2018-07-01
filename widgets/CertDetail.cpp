/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CertDetail.h"
#include "KeyDetail.h"
#include "MainWindow.h"
#include "distname.h"
#include "clicklabel.h"
#include "lib/func.h"
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QMessageBox>

CertDetail::CertDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	showConf = false;
	keySqlId = QVariant();
	issuerSqlId = QVariant();
	myPubKey = NULL;
}

void CertDetail::on_showExt_clicked()
{
	if (showConf) {
		showConf = false;
		v3extensions->document()->setHtml(exts);
		showExt->setText(tr("Show config"));
	} else {
		showConf = true;
		v3extensions->document()->setPlainText(conf);
		showExt->setText(tr("Show extensions"));
	}

}

void CertDetail::setX509super(pki_x509super *x)
{
	descr->setText(x->getIntName());

	// examine the key
	pki_key *key= x->getRefKey();
	myPubKey = x->getPubKey();
	if (key) {
		privKey->setText(key->getIntName());
		privKey->setClickText(key->getSqlItemId().toString());
		if (key->isPrivKey()) {
			privKey->setGreen();
		} else {
			privKey->setRed();
		}
		keySqlId = key->getSqlItemId();
	} else if (myPubKey) {
		privKey->setText(tr("Show public key"));
		privKey->setRed();
		connect(privKey, SIGNAL(doubleClicked(QString)),
			this,    SLOT(showPubKey()));
		myPubKey->setIntName(x->getIntName());
		myPubKey->setComment(tr("This key is not in the database."));
	} else {
		privKey->setText(tr("Not available"));
		privKey->setDisabled(true);
		privKey->disableToolTip();
	}

	// details of the subject
	subject->setX509name(x->getSubject());

	// V3 extensions
	extList el = x->getV3ext();
	if (el.count() == 0) {
		tabwidget->removeTab(4);
	} else {
		exts = el.getHtml("<br>");
		el.genGenericConf(&conf);
		v3extensions->document()->setHtml(exts);
	}

	// Algorithm
	sigAlgo->setText(x->getSigAlg());
	connect(sigAlgo, SIGNAL(doubleClicked(QString)),
		MainWindow::getResolver(), SLOT(searchOid(QString)));

	// Comment
	comment->setPlainText(x->getComment());
}

void CertDetail::setCert(pki_x509 *cert)
{
	image->setPixmap(*MainWindow::certImg);
	headerLabel->setText(tr("Details of the Certificate"));
	try {
		setX509super(cert);

		// No attributes
		tabwidget->removeTab(3);

		// examine the signature
		if (cert->getSigner() == NULL) {
			signature->setText(tr("Signer unknown"));
			signature->setDisabled(true);
			signature->disableToolTip();
		} else if (cert == cert->getSigner())  {
			signature->setText(tr("Self signed"));
			signature->setGreen();
			signature->disableToolTip();
		} else {
			pki_x509 *issuer = cert->getSigner();
			signature->setText(issuer->getIntName());
			signature->setClickText(issuer->getSqlItemId().toString());
			signature->setGreen();
			issuerSqlId = issuer->getSqlItemId();
		}

		// the serial
		serialNr->setText(cert->getSerial());

		// details of the issuer
		issuer->setX509name(cert->getIssuerName());

		// The dates
		notBefore->setText(cert->getNotBefore().toPretty());
		notBefore->setToolTip(cert->getNotBefore().toPrettyGMT());
		notAfter->setText(cert->getNotAfter().toPretty());
		notAfter->setToolTip(cert->getNotAfter().toPrettyGMT());

		// validation of the Date
		dateValid->disableToolTip();
		if (cert->isRevoked()) {
			x509rev rev = cert->getRevocation();
			dateValid->setText(tr("Revoked: ") +
			rev.getDate().toPretty());
			dateValid->setRed();
			dateValid->setToolTip(rev.getDate().toPrettyGMT());
		} else if (!cert->checkDate()) {
			dateValid->setText(tr("Not valid"));
			dateValid->setRed();
		} else {
			dateValid->setGreen();
			dateValid->setText(tr("Valid"));
		}
		// the fingerprints
		fpMD5->setText(cert->fingerprint(EVP_md5()));
		fpSHA1->setText(cert->fingerprint(EVP_sha1()));
		QString fp = cert->fingerprint(EVP_sha256());
		int x = fp.size() / 2;
		fp = fp.mid(0,x) + "\n" + fp.mid(x+1, -1);
		fpSHA256->setText(fp);

		openssl_error();
	} catch (errorEx &err) {
		XCA_WARN(err.getString());
	}
}

void CertDetail::setReq(pki_x509req *req)
{
	image->setPixmap(*MainWindow::csrImg);
	headerLabel->setText(tr("Details of the certificate signing request"));
	try {
		setX509super(req);

		// No issuer
		tabwidget->removeTab(2);

		// verification
		if (!req->verify() ) {
			signature->setRed();
			signature->setText("Failed");
		} else {
			signature->setGreen();
			signature->setText("PKCS#10");
		}
		signature->disableToolTip();
		fingerprints->hide();
		validity->hide();
		serialLabel->hide();
		serialNr->hide();

		// The non extension attributes
		int cnt = X509_REQ_get_attr_count(req->getReq());
		int added = 0;
		QGridLayout *attrLayout = new QGridLayout(attributes);
		attrLayout->setAlignment(Qt::AlignTop);
		attrLayout->setSpacing(6);
		attrLayout->setMargin(11);

		for (int i = 0, ii = 0; i<cnt; i++) {
			int nid;
			QLabel *label;
			QString trans;
			X509_ATTRIBUTE *att = X509_REQ_get_attr(req->getReq(), i);

			nid = OBJ_obj2nid(X509_ATTRIBUTE_get0_object(att));

			if (X509_REQ_extension_nid(nid)) {
				continue;
			}
			label = new QLabel(this);
			trans = dn_translations[nid];
			if (Settings["translate_dn"] && !trans.isEmpty()) {
				label->setText(trans);
				label->setToolTip(QString(OBJ_nid2sn(nid)));
			} else {
				label->setText(QString(OBJ_nid2ln(nid)));
				label->setToolTip(trans);
			}

			label->setText(QString(OBJ_nid2ln(nid)));
			label->setToolTip(QString(OBJ_nid2sn(nid)));
			attrLayout->addWidget(label, ii, 0);
			added++;

			int count = X509_ATTRIBUTE_count(att);
			for (int j=0; j<count; j++) {
				ASN1_TYPE *at = X509_ATTRIBUTE_get0_type(att, j);
				label = labelFromAsn1String(at->value.asn1_string);
				attrLayout->addWidget(label, ii, j +1);
			}
			ii++;
		}
		if (!added) {
			tabwidget->removeTab(2);
		}
		openssl_error();
	} catch (errorEx &err) {
		XCA_WARN(err.getString());
	}
}

QLabel *CertDetail::labelFromAsn1String(ASN1_STRING *s)
{
	QLabel *label;
	label = new CopyLabel(this);
	label->setText(asn1ToQString(s));
	label->setToolTip(QString(ASN1_tag2str(s->type)));
	return label;
}

void CertDetail::itemChanged(pki_base *pki)
{
	if (pki->getSqlItemId() == keySqlId)
		privKey->setText(pki->getIntName());

	if (pki->getSqlItemId() == issuerSqlId)
		signature->setText(pki->getIntName());
}

void CertDetail::showPubKey()
{
	if (!myPubKey)
		return;
	KeyDetail *dlg = new KeyDetail(this);
	if (!dlg)
		return;
	dlg->setKey(myPubKey);
	dlg->keyDesc->setReadOnly(true);
	dlg->comment->setReadOnly(true);
	dlg->exec();
	delete dlg;
}

CertDetail::~CertDetail()
{
	if (myPubKey)
		delete myPubKey;
}
