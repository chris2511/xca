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
#include "XcaWarning.h"
#include "Help.h"
#include "OidResolver.h"
#include "lib/func.h"
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QMessageBox>

CertDetail::CertDetail(QWidget *w)
	: QDialog(w ?: mainwin), keySqlId(), issuerSqlId(), thisSqlId()
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	showConf = false;
	myPubKey = NULL;
	tmpPubKey = NULL;

	Database.connectToDbChangeEvt(this, SLOT(itemChanged(pki_base*)));
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
	thisSqlId = x->getSqlItemId();

	// examine the key
	myPubKey = x->getRefKey();
	if (myPubKey) {
		privKey->setText(myPubKey->getIntName());
		privKey->setClickText(myPubKey->getSqlItemId().toString());
		if (myPubKey->isPrivKey()) {
			privKey->setGreen();
		} else {
			privKey->setRed();
		}
	} else {
		tmpPubKey = myPubKey = x->getPubKey();
		privKey->setText(tr("Show public key"));
		privKey->setRed();
		myPubKey->setIntName(x->getIntName());
		myPubKey->setComment(tr("This key is not in the database."));
	}

	if (!myPubKey) {
		privKey->setText(tr("Not available"));
		privKey->setDisabled(true);
		privKey->disableToolTip();
	} else {
		keySqlId = myPubKey->getSqlItemId();
	}
	connect(privKey, SIGNAL(doubleClicked(QString)),
		this, SLOT(showPubKey()));

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

	setCert(dynamic_cast<pki_x509*>(x));
	setReq(dynamic_cast<pki_x509req*>(x));
}

void CertDetail::setCert(pki_x509 *cert)
{
	if (!cert)
		return;
	image->setPixmap(QPixmap(":certImg"));
	headerLabel->setText(tr("Details of the Certificate"));
	mainwin->helpdlg->register_ctxhelp_button(this, "certdetail");
	try {
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

			connect(signature, SIGNAL(doubleClicked(QString)),
				this, SLOT(showIssuer()));
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
			dateValid->setText(tr("Revoked at %1")
				.arg(rev.getDate().toPretty()));
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
	if (!req)
		return;
	image->setPixmap(QPixmap(":csrImg"));
	headerLabel->setText(tr("Details of the certificate signing request"));
	mainwin->helpdlg->register_ctxhelp_button(this, "csrdetail");
	try {
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
	QVariant pkiSqlId = pki->getSqlItemId();

	if (pkiSqlId == keySqlId)
		privKey->setText(pki->getIntName());
	if (pkiSqlId == issuerSqlId)
		signature->setText(pki->getIntName());
	if (pkiSqlId == thisSqlId)
		descr->setText(pki->getIntName());
}

void CertDetail::showPubKey()
{
	KeyDetail::showKey(this, myPubKey, !keySqlId.isValid());
}

void CertDetail::showIssuer()
{
	showCert(this, Store.lookupPki<pki_x509>(issuerSqlId));
}

void CertDetail::showCert(QWidget *parent, pki_x509super *x)
{
	if (!x)
		return;
	CertDetail *dlg = new CertDetail(parent);
	if (!dlg)
                return;
	dlg->setX509super(x);
	if (dlg->exec()) {
		db_base *db = Database.modelForPki(x);
		if (!db) {
			x->setIntName(dlg->descr->text());
			x->setComment(dlg->comment->toPlainText());
		} else {
			db->updateItem(x, dlg->descr->text(),
					dlg->comment->toPlainText());
		}
        }
        delete dlg;
}

CertDetail::~CertDetail()
{
	delete tmpPubKey;
}
