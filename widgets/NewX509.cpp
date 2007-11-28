/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewX509.h"
#include <qcheckbox.h>
#include <qcombobox.h>
#include <qradiobutton.h>
#include <qmessagebox.h>
#include <qlineedit.h>
#include <qlabel.h>
#include <qpixmap.h>
#include <qpushbutton.h>
#include <qvalidator.h>
#include "MainWindow.h"
#include "v3ext.h"
#include "lib/x509name.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/oid.h"
#include "lib/func.h"

int NewX509::name_nid[] = {
	NID_countryName,
	NID_stateOrProvinceName,
	NID_localityName,
	NID_organizationName,
	NID_organizationalUnitName,
	NID_commonName,
	NID_pkcs9_emailAddress
};

NewX509::NewX509(QWidget *parent)
	:QDialog(parent)
{
	int i;
	eku_nid = *MainWindow::eku_nid;
	dn_nid = *MainWindow::dn_nid;
	aia_nid = *MainWindow::aia_nid;
	attr_nid << NID_pkcs9_unstructuredName << NID_pkcs9_challengePassword;

	QStringList sl;

	setupUi(this);

	/* temporary storage for creating temporary X509V3_CTX */
	ctx_cert = NULL;

	sl << "Type" << "Content";
	extDNlist->setColumnCount(2);
	extDNlist->setHorizontalHeaderLabels(sl);
	setWindowTitle(tr(XCA_TITLE));

	nsImg->setPixmap(*MainWindow::nsImg);
	//setFont( tFont );
	serialNr->setValidator( new QRegExpValidator(QRegExp("[0-9a-fA-F]*"), this));
	QStringList strings;

	// are there any useable private keys  ?
	newKeyDone("");

	// any PKCS#10 requests to be used ?
	strings = MainWindow::reqs->getDesc();
	if (strings.isEmpty()) {
		fromReqCB->setDisabled(true);
		fromReqCB->setChecked(false);
	}
	else {
		reqList->insertItems(0, strings);
	}
	on_fromReqCB_clicked();

	// How about signing certificates ?
	strings = MainWindow::certs->getSignerDesc();
	if (strings.isEmpty()) {
		foreignSignRB->setDisabled(true);
	} else {
		certList->insertItems(0, strings);
	}
#ifdef WG_QA_SERIAL
	selfQASignRB = new QRadioButton(signerBox);
	setTabOrder(serialNr, selfQASignRB);
	setTabOrder(selfQASignRB, foreignSignRB);
	selfQASignRB->setText(tr(
			"Create a &self signed certificate with a MD5-hashed QA serial"));
	QBoxLayout *l = (QBoxLayout *)signerBox->layout();
	l->insertWidget(1, selfQASignRB);
#endif
	// set dates to now and now + 1 year
	a1time a;
	notBefore->setDate(a.now());
	notAfter->setDate(a.now(60*60*24*365));

	// settings for the templates ....
	strings.clear();
	strings = MainWindow::temps->getDescPredefs();
	tempList->insertItems(0, strings);

	// setup Extended keyusage
	for (i=0; i < eku_nid.count(); i++)
		ekeyUsage->addItem(OBJ_nid2ln(eku_nid[i]));

	// setup Distinguished Name
	for (i=0; i < dn_nid.count(); i++)
		extDNobj->addItem(OBJ_nid2ln(dn_nid[i]));

	// setup Authority Info Access
	for (i=0; i < aia_nid.count(); i++)
		aiaOid->addItem(OBJ_nid2ln(aia_nid[i]));

	// init the X509 v3 context
	X509V3_set_ctx(&ext_ctx, NULL , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb(&ext_ctx);

	// setup the list of x509nameEntrys
	name_ptr[0] = countryName;
	name_ptr[1] = stateOrProvinceName;
	name_ptr[2] = localityName;
	name_ptr[3] = organisationName;
	name_ptr[4] = organisationalUnitName;
	name_ptr[5] = commonName;
	name_ptr[6] = emailAddress;

	// Setup Request Attributes
	if (attrWidget->layout())
		delete attrWidget->layout();
	QGridLayout *attrLayout = new QGridLayout(attrWidget);
	attrLayout->setAlignment(Qt::AlignTop);
	attrLayout->setSpacing(6);
	attrLayout->setMargin(0);
	attr_edit.clear();
	for (i=0; i < attr_nid.count(); i++) {
		QLabel *label;
		QLineEdit *edit;
		int nid = attr_nid[i];
		label = new QLabel(this);
		label->setText(QString(OBJ_nid2ln(nid)));
		label->setToolTip(QString(OBJ_nid2sn(nid)));
		edit = new QLineEdit(this);
		attr_edit << edit;
		attrLayout->addWidget(label, i, 0);
		attrLayout->addWidget(edit, i, 1);
	}
	// last polish
	on_certList_currentIndexChanged(0);
	certList->setDisabled(true);
	checkAuthKeyId();
	tabWidget->setCurrentIndex(0);
	attrWidget->hide();
	pt = none;
}

void NewX509::setRequest()
{
	reqWidget->hide();
	attrWidget->show();

	signerBox->setEnabled(false);
	timewidget->setEnabled(false);
	capt->setText(tr("Create Certificate signing request"));
	setImage(MainWindow::csrImg);
	pt = x509_req;
}

NewX509::~NewX509()
{
	if (ctx_cert)
		delete(ctx_cert);
}

void NewX509::addReqAttributes(pki_x509req *req)
{
	for (int i=0; i < attr_nid.count(); i++) {
		req->addAttribute(attr_nid[i], attr_edit[i]->text());
	}
}

void NewX509::setTemp(pki_temp *temp)
{
	QString text = tr("Create ");
	if (temp->getIntName() != "--") {
		description->setText(temp->getIntName());
		description->setDisabled(true);
		text = tr("Edit ");
	}
	capt->setText(text + tr("XCA template"));
	tabWidget->removeTab(0);
	privKeyBox->setEnabled(false);
	validityBox->setEnabled(false);
	setImage(MainWindow::tempImg);
	pt = tmpl;
}

void NewX509::setCert()
{
	capt->setText(tr("Create x509 Certificate"));
	setImage(MainWindow::certImg);
	pt = x509;
}

void NewX509::setImage(QPixmap *img)
{
	image->setPixmap(*img);
}

void NewX509::defineTemplate(pki_temp *temp)
{
	fromTemplate(temp);
	templateChanged(temp);
	tempList->setEnabled(false);
}

void NewX509::defineRequest(pki_x509req *req)
{
	if (!req)
		return;
	fromReqCB->setEnabled(true);
	fromReqCB->setChecked(true);
	QString reqname = req->getIntName();
	reqList->setCurrentIndex(reqList->findText(reqname));
	on_fromReqCB_clicked();
}

void NewX509::defineSigner(pki_x509 *defcert)
{
	int index;
	// suggested from: Andrey Brindeew <abr@abr.pp.ru>
	if (defcert && defcert->canSign() ) {
		QString name = defcert->getIntName();
		foreignSignRB->setChecked(true);
		certList->setEnabled(true);
		if ((index = certList->findText(name)) >= 0) {
			certList->setCurrentIndex(index);
		}
	}
}


int NewX509::lb2int(QListWidget *lb)
{
	int i, x=0, c=lb->count();
	QListWidgetItem *item;

	for (i=0; i<c; i++) {
		item = lb->item(i);
		if (lb->isItemSelected(item)){
			x |= 1<<i;
		}
	}
	return x;
}


void NewX509::int2lb(QListWidget *lb, int x)
{
	int i, c=lb->count();
	QListWidgetItem *item;

	for (i=0; i<c; i++) {
		item = lb->item(i);
		lb->setItemSelected(item, (1<<i) & x);
	}
}


void NewX509::fromTemplate(pki_temp *temp)
{
	setX509name(temp->xname);
	subAltName->setText(temp->subAltName);
	issAltName->setText(temp->issAltName);
	crlDist->setText(temp->crlDist);
	setAuthInfAcc_string(temp->authInfAcc);
	nsComment->setText(temp->nsComment);
	nsBaseUrl->setText(temp->nsBaseUrl);
	nsRevocationUrl->setText(temp->nsRevocationUrl);
	nsCARevocationUrl->setText(temp->nsCARevocationUrl);
	nsRenewalUrl->setText(temp->nsRenewalUrl);
	nsCaPolicyUrl->setText(temp->nsCaPolicyUrl);
	nsSslServerName->setText(temp->nsSslServerName);
#warning settings
	int2lb(nsCertType, temp->nsCertType);
	basicCA->setCurrentIndex(temp->ca);
	bcCritical->setChecked(temp->bcCrit);
	kuCritical->setChecked(temp->keyUseCrit);
	ekuCritical->setChecked(temp->eKeyUseCrit);
	subKey->setChecked(temp->subKey);
	authKey->setChecked(temp->authKey);
	int2lb(keyUsage, temp->keyUse);
	int2lb(ekeyUsage, temp->eKeyUse);
	validNumber->setText(QString::number(temp->validN));
	validRange->setCurrentIndex(temp->validM);
	midnightCB->setChecked(temp->validMidn);
	if (temp->pathLen) {
		basicPath->setText(QString::number(temp->pathLen));
	}
	notBefore->setNow();
	on_applyTime_clicked();
}

void NewX509::toTemplate(pki_temp *temp)
{
	temp->setIntName(description->text());
	temp->xname = getX509name();
	temp->subAltName = subAltName->text();
	temp->issAltName = issAltName->text();
	temp->crlDist = crlDist->text();
	temp->authInfAcc = getAuthInfAcc_string();
	temp->nsComment = nsComment->text();
	temp->nsBaseUrl = nsBaseUrl->text();
	temp->nsRevocationUrl = nsRevocationUrl->text();
	temp->nsCARevocationUrl = nsCARevocationUrl->text();
	temp->nsRenewalUrl = nsRenewalUrl->text();
	temp->nsCaPolicyUrl = nsCaPolicyUrl->text();
	temp->nsSslServerName = nsSslServerName->text();
	temp->nsCertType =  lb2int(nsCertType);
	temp->ca = basicCA->currentIndex();
	temp->bcCrit = bcCritical->isChecked();
	temp->keyUseCrit = kuCritical->isChecked();
	temp->eKeyUseCrit = ekuCritical->isChecked();
	temp->subKey = subKey->isChecked();
	temp->authKey = authKey->isChecked();
	temp->keyUse = lb2int(keyUsage);
	temp->eKeyUse = lb2int(ekeyUsage);
	temp->validN = validNumber->text().toInt();
	temp->validM = validRange->currentIndex();
	temp->pathLen = basicPath->text().toInt();
	temp->validMidn = midnightCB->isChecked();
}

void NewX509::on_fromReqCB_clicked()
{
	bool request = fromReqCB->isChecked();
	bool subj_tab_present = tabWidget->widget(1) == tab_1;

	if (request && subj_tab_present)
		tabWidget->removeTab(1);
	else if (!request && !subj_tab_present)
		tabWidget->insertTab(1, tab_1, tr("Subject"));

	reqList->setEnabled(request);
	copyReqExtCB->setEnabled(request);
	showReqBut->setEnabled(request);
	switchHashAlgo();
}


void NewX509::on_keyList_currentIndexChanged(const QString &)
{
	switchHashAlgo();
}

void NewX509::on_reqList_currentIndexChanged(const QString &)
{
	switchHashAlgo();
}

void NewX509::switchHashAlgo()
{
	pki_key *key;
	pki_x509super *sig;

	if (foreignSignRB->isChecked())
		sig = getSelectedSigner();
	else if (fromReqCB->isChecked())
		sig = getSelectedReq();
	else
		sig = NULL;

	key = sig ? sig->getRefKey() : getSelectedKey();
	if (key && key->getType() == EVP_PKEY_DSA)
		hashAlgo->setDsa(true);
	else
		hashAlgo->setDsa(false);
}

void NewX509::on_showReqBut_clicked()
{
	QString req = reqList->currentText();
	emit showReq(req);
}

void NewX509::on_genKeyBUT_clicked()
{
	emit genKey();
}

void NewX509::on_certList_currentIndexChanged(int)
{
	a1time snb, sna;
	pki_x509 *cert = getSelectedSigner();

	switchHashAlgo();

	if (!cert)
		return;

	QString templ = cert->getTemplate();
	snb = cert->getNotBefore();
	sna = cert->getNotAfter();
	if (snb > notBefore->getDate())
		notBefore->setDate(snb);
	if (sna < notAfter->getDate())
		notAfter->setDate(sna);

	checkAuthKeyId();
	if (templ.isEmpty())
		return;

	templateChanged(templ);
}


void NewX509::templateChanged(QString tempname)
{
	int index;
	if (!tempList->isEnabled())
		return;
	if ((index = tempList->findText(tempname)) <0)
		return;

	tempList->setCurrentIndex(index);
}


void NewX509::templateChanged(pki_temp *templ)
{
	QString tempname = templ->getIntName();
	templateChanged(tempname);
}

void NewX509::on_applyTemplate_clicked()
{
	pki_temp *temp = NULL;
	if (!tempList->isEnabled())
		return;
	QString name = tempList->currentText();
	if (name.isEmpty())
		return;
	temp = (pki_temp *)MainWindow::temps->getByName(name);
	if (!temp)
		return;
	fromTemplate(temp);
}

void NewX509::checkAuthKeyId()
{
	bool enabled = false;

	if (foreignSignRB->isChecked()) {
		if (getSelectedSigner()->hasExtension(NID_subject_key_identifier)) {
			enabled = true;
		}
	}
	authKey->setEnabled(enabled);
}

void NewX509::on_foreignSignRB_toggled(bool checked)
{
	checkAuthKeyId();
	switchHashAlgo();
	certList->setEnabled(checked);
}

void NewX509::on_selfSignRB_toggled(bool checked)
{
	serialNr->setEnabled(checked);
}

void NewX509::on_subKey_clicked()
{
	checkAuthKeyId();
}

void NewX509::newKeyDone(QString name)
{
	QStringList keys;
	private_keys = MainWindow::keys->get0PrivateDesc(true);
	private_keys0 = MainWindow::keys->get0PrivateDesc(false);
	keyList->clear();
	if (usedKeysToo->isChecked())
		keys = private_keys;
	else
		keys = private_keys0;

	keyList->insertItems(0, keys);
	if (name.isEmpty() && keys.count() >0)
		name = keys[0];
	keyList->setCurrentIndex(keys.indexOf(name));
}

void NewX509::on_usedKeysToo_toggled(bool)
{
	QString cur = keyList->currentText();
	QStringList keys;
	keyList->clear();
	if (usedKeysToo->isChecked())
		keys = private_keys;
	else
		keys = private_keys0;

	keyList->insertItems(0, keys);
	keyList->setCurrentIndex(keys.indexOf(cur));
}

pki_key *NewX509::getSelectedKey()
{
	QString name = pki_key::removeTypeFromIntName(keyList->currentText());
	return (pki_key *)MainWindow::keys->getByName(name);
}

pki_x509 *NewX509::getSelectedSigner()
{
	return (pki_x509 *)MainWindow::certs->getByName(certList->currentText());
}

pki_x509req *NewX509::getSelectedReq()
{
	return (pki_x509req *)MainWindow::reqs->getByName(reqList->currentText());
}

x509name NewX509::getX509name(int _throw)
{
	x509name x;
	int j, row, nid;

	try {
		for (j = 0; j<EXPLICIT_NAME_CNT; j++) {
			nid = name_nid[j];
			x.addEntryByNid(nid, name_ptr[j]->text());
		}
		row = extDNlist->rowCount();
		for (j=0; j<row; j++) {
			nid = OBJ_ln2nid(CCHAR(extDNlist->item(j,0)->text()));
			x.addEntryByNid(nid, extDNlist->item(j,1)->text());
		}
	} catch (errorEx &err) {
		if (!err.isEmpty()) {
			if (_throw)
				throw err;
			else
				QMessageBox::warning(this, XCA_TITLE, err.getString());
		}
	}
	return x;
}

void NewX509::setX509name(const x509name &n)
{
	int i,j;
#if QT_VERSION >= 0x040200
	extDNlist->clearContents();
#else
	extDNlist->clear();
#endif
	for (j=0; j<EXPLICIT_NAME_CNT; j++) {
		name_ptr[j]->setText("");
	}
	for (i=0, j=0; i< n.entryCount(); i++) {
		int nid = n.nid(i);
		QStringList sl = n.entryList(i);
		for ( ; j<EXPLICIT_NAME_CNT; j++) {
			if (nid == name_nid[j] && name_ptr[j]->text().isEmpty()) {
				name_ptr[j]->setText(sl[2]);
				break;
			}
		}
		if (j == EXPLICIT_NAME_CNT) {
			QTableWidgetItem *tw;
			int row;

			row = extDNlist->rowCount();
			extDNlist->setRowCount(row+1);

			for (int i=0; i<2; i++) {
				tw = new QTableWidgetItem(sl[i+1]);
				extDNlist->setItem(row, i, tw);
			}
		}
	}
}

void NewX509::on_extDNadd_clicked()
{
	QTableWidgetItem *tw;
	int row;

	row = extDNlist->rowCount();
	extDNlist->setRowCount(row+1);

	tw = new QTableWidgetItem(extDNobj->currentText());
	extDNlist->setItem(row, 0, tw);

	tw = new QTableWidgetItem(extDNname->text());
	extDNlist->setItem(row, 1, tw);
}

void NewX509::on_extDNdel_clicked()
{
	extDNlist->removeRow(extDNlist->currentRow());
}

void NewX509::on_applyTime_clicked()
{
	applyTD(this, validNumber->text().toInt(), validRange->currentIndex(),
			midnightCB->isChecked(), notBefore, notAfter);
}

void NewX509::setupTmpCtx()
{
	pki_x509 *signcert;
	pki_x509req *req = NULL;
	a1int serial;

	// initially create temporary ctx cert
	if (ctx_cert)
		delete(ctx_cert);
	ctx_cert = new pki_x509();
	if (fromReqCB->isChecked()) {
		req = getSelectedReq();
		ctx_cert->setSubject(req->getSubject());
	} else {
		ctx_cert->setSubject(getX509name());
	}
	// Step 2 - select Signing
	if (foreignSignRB->isChecked()) {
		signcert = getSelectedSigner();
		serial = signcert->getCaSerial();
	} else {
		signcert = ctx_cert;
		ctx_cert->setIssuer(ctx_cert->getSubject());
		serial.setHex(serialNr->text());
	}
	ctx_cert->setSerial(serial);
	initCtx(ctx_cert, signcert, req);
	ctx_cert->addV3ext(getSubKeyIdent());
}

void NewX509::editV3ext(QLineEdit *le, QString types, int n)
{
	v3ext *dlg;

	dlg = new v3ext(this);
	setupTmpCtx();
	dlg->addInfo(le, types.split(',' ), n, &ext_ctx);
	dlg->exec();
	delete(dlg);
}

void NewX509::on_adv_validate_clicked()
{
	if (!nconf_data->isReadOnly()) {
		QString errtxt;
		extList el;
		pki_base::ign_openssl_error();
		QString result;
		setupTmpCtx();
		v3ext_backup = nconf_data->toPlainText();
		el = getGuiExt();
		el += getNetscapeExt();
		el.delInvalid();
		if (el.size() > 0) {
			result = "<h2><center>Other Tabs</center></h2><p>\n";
			result += el.getHtml("<br>");
		}
		el = getAdvanced();
		if (el.size() > 0) {
			if (!result.isEmpty())
				result += "\n<hr>\n";
			result += "<h2><center>Advanced Tab</center></h2><p>\n";
			result += el.getHtml("<br>");
		}
		while (int i = ERR_get_error() ) {
			errtxt += ERR_error_string(i, NULL);
			errtxt += "<br>\n";
		}
		if (!errtxt.isEmpty()) {
			if (!result.isEmpty())
				result += "\n<hr>\n";
			result += "<h2><center>Errors</center></h2><p>\n";
			result += errtxt;
		}
		nconf_data->document()->setHtml(result);
		nconf_data->setReadOnly(true);

		adv_validate->setText(tr("Edit"));
	} else {
		nconf_data->document()->setPlainText(v3ext_backup);
		nconf_data->setReadOnly(false);
		adv_validate->setText(tr("Validate"));
	}
	pki_base::ign_openssl_error();
}

void NewX509::on_editSubAlt_clicked()
{
	QString s = "email,RID,URI,DNS,IP,otherName";
	if (pt != x509_req)
		s = QString("email:copy,") + s;
	editV3ext(subAltName, s, NID_subject_alt_name);
}

void NewX509::on_editIssAlt_clicked()
{
	QString s = "email,RID,URI,DNS,IP,otherName";
	if (pt != x509_req)
	        s = QString("issuer:copy,") +s ;
	editV3ext(issAltName, s, NID_issuer_alt_name);
}

void NewX509::on_editCrlDist_clicked()
{
	editV3ext(crlDist, "URI", NID_crl_distribution_points);
}

void NewX509::on_editAuthInfAcc_clicked()
{
	editV3ext(authInfAcc, "email,RID,URI,DNS,IP", NID_info_access);
}

void NewX509::on_tabWidget_currentChanged(int)
{
	/* reset advanced tab to editable text */
	if (nconf_data->isReadOnly())
		on_adv_validate_clicked();
}

QString NewX509::mandatoryDnRemain()
{
	QStringList dnl = MainWindow::mandatory_dn.split(",");
	x509name n;
	int i;

	if (fromReqCB->isChecked())
		n = getSelectedReq()->getSubject();
	else
		n = getX509name();

	for (i=0; i< n.entryCount(); i++) {
		int j = dnl.indexOf(QString(OBJ_nid2sn(n.nid(i))));
		if (j>=0)
			dnl.removeAt(j);
	}
	return dnl.join(",");
}

void NewX509::on_okButton_clicked()
{
	on_tabWidget_currentChanged(0);

	try {
		getX509name(1);
	} catch (errorEx &err) {
		if (QMessageBox::warning(this, tr(XCA_TITLE), err.getString(),
				tr("Ok"), tr("Abort rollout")) == 1)
		{
			reject();
		}
		return;
	}

	if (description->text().isEmpty() && !fromReqCB->isChecked()) {
		if (commonName->text().isEmpty()) {
			if (QMessageBox::warning(this, tr(XCA_TITLE),
					tr("The internal name and the common name are empty.\n"
					"Please set at least the internal name."),
					tr("Ok"), tr("Abort rollout")) == 1)
			{
				reject();
			}
			return;
		} else {
			description->setText(commonName->text());
		}
	}

	if ( keyList->count() == 0 &&
		keyList->isEnabled() &&
		!fromReqCB->isChecked())
	{
		if (QMessageBox::warning(this, tr(XCA_TITLE),
				tr("There is no Key selected for signing."),
				tr("Ok"), tr("Abort rollout")) == 1)
		{
			reject();
		}
		return;
	}

	QString unsetDN;
	if (pt != tmpl)
		unsetDN = mandatoryDnRemain();
	if (!unsetDN.isEmpty())
	{
		switch (QMessageBox::warning(this, tr(XCA_TITLE),
				tr("The following distinguished name entries are empty,\n"
					"though you have declared them as mandatory "
					"in the options menu:\n") + unsetDN,
				tr("Ok"), tr("Abort rollout"),
				tr("Continue rollout")))
		{
			case -1:
			case 0:
				return;
			case 1:
				reject();
				return;
		}
	}
	if (notBefore->getDate().get_utc() == NULL ||
				notAfter->getDate().get_utc() == NULL) {
		switch (QMessageBox::warning(this, tr(XCA_TITLE),
			tr("The validity dates are out of range (1950 - 2049) to create "
				"valid certificates. If you continue, your client may "
				"reject the certificate."),
			tr("Ok"), tr("Abort rollout"), tr("Continue rollout")))
		{
			case -1:
			case 0:
				return;
			case 1:
				reject();
				return;
		}
	}
	if (notBefore->getDate() > notAfter->getDate()) {
		switch (QMessageBox::warning(this, tr(XCA_TITLE),
			tr("The certificate will be out of date before it becomes valid. "
				"You most probably mixed up both dates."),
			tr("Ok"), tr("Abort rollout"), tr("Continue rollout")))
		{
			case -1:
			case 0:
				return;
			case 1:
				reject();
				return;
		}
	}
	accept();
}
