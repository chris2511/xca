/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewX509.h"
#include <QCheckBox>
#include <QComboBox>
#include <QRadioButton>
#include <QMessageBox>
#include <QLineEdit>
#include <QLabel>
#include <QPixmap>
#include <QPushButton>
#include <QValidator>
#include "MainWindow.h"
#include "v3ext.h"
#include "lib/x509name.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/oid.h"
#include "lib/func.h"

NewX509::NewX509(QWidget *parent)
	:QDialog(parent)
{
	int i;
	eku_nid = *MainWindow::eku_nid;
	dn_nid = *MainWindow::dn_nid;
	aia_nid = *MainWindow::aia_nid;
	attr_nid << NID_pkcs9_unstructuredName << NID_pkcs9_challengePassword;
	foreach(QString dn, MainWindow::explicit_dn.split(","))
		expl_dn_nid << OBJ_sn2nid(CCHAR(dn));

	QStringList keys;

	setupUi(this);

	/* temporary storage for creating temporary X509V3_CTX */
	ctx_cert = NULL;

	foreach(int nid, dn_nid)
		keys << QString(OBJ_nid2ln(nid));

	extDNlist->setKeys(keys);
	extDNlist->setInfoLabel(extDNinfo);
	connect(extDNlist->itemDelegateForColumn(1),
		SIGNAL(setupLineEdit(const QString &, QLineEdit *)),
		this, SLOT(setupExtDNwidget(const QString &, QLineEdit *)));
	connect(subAltName, SIGNAL(textChanged(const QString &)),
                this, SLOT(checkSubAltName(const QString &)));
	connect(issAltName, SIGNAL(textChanged(const QString &)),
                this, SLOT(checkIssAltName(const QString &)));
	connect(crlDist, SIGNAL(textChanged(const QString &)),
                this, SLOT(checkCrlDist(const QString &)));
	connect(authInfAcc, SIGNAL(textChanged(const QString &)),
                this, SLOT(checkAuthInfAcc(const QString &)));

	setWindowTitle(XCA_TITLE);

	for (i=0; i<tabWidget->count(); i++) {
		tabnames << tabWidget->tabText(i);
	}

	nsImg->setPixmap(*MainWindow::nsImg);
	serialNr->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]*"), this));
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
	validNumber->setText("1");
	validRange->setCurrentIndex(2);
	on_applyTime_clicked();

	// settings for the templates ....
	strings.clear();
	strings = MainWindow::temps->getDescPredefs();
	tempList->insertItems(0, strings);

	// setup Extended keyusage
	foreach(int nid, eku_nid)
		ekeyUsage->addItem(OBJ_nid2ln(nid));

	// setup Authority Info Access
	foreach(int nid, aia_nid)
		aiaOid->addItem(OBJ_nid2ln(nid));

	// init the X509 v3 context
	X509V3_set_ctx(&ext_ctx, NULL , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb(&ext_ctx);

	// Setup dnWidget
	if (dnWidget->layout())
		delete dnWidget->layout();
	QGridLayout *dnLayout = new QGridLayout(dnWidget);
	dnLayout->setAlignment(Qt::AlignTop);
	dnLayout->setSpacing(6);
	dnLayout->setMargin(0);
	int n = 1, col = 0;

	description = new QLineEdit(this);
	description->setToolTip(tr("This name is only used internally and does not appear in the resulting certificate"));
	QLabel *label = new QLabel(this);
	label->setText(tr("Internal name"));
	dnLayout->addWidget(label, 0, 0);
	dnLayout->addWidget(description, 0, 1);

	QWidget::setTabOrder(description, extDNlist);
	QWidget *old = description;
	foreach(int nid, expl_dn_nid) {
		DoubleClickLabel *label;
		QLineEdit *edit;
		QString trans = dn_translations[nid];

		label = new DoubleClickLabel(this);
		if (translate_dn && !trans.isEmpty()) {
			label->setText(trans);
			label->setToolTip(QString("[%1] %2")
				.arg(OBJ_nid2sn(nid)).arg(OBJ_nid2ln(nid)));
		} else {
			label->setText(OBJ_nid2ln(nid));
			label->setToolTip(QString("[%1] %2")
				.arg(OBJ_nid2sn(nid)).arg(trans));
		}
		label->setClickText(OBJ_nid2sn(nid));
		connect(label, SIGNAL(doubleClicked(QString)),
                        MainWindow::getResolver(), SLOT(searchOid(QString)));
		edit = new QLineEdit(this);
		setupLineEditByNid(nid, edit);
		nameEdits << nameEdit(nid, edit, label);

		dnLayout->addWidget(label, n, col);
		dnLayout->addWidget(edit, n, col +1);
		n++;
		if (n > expl_dn_nid.size()/2 && col == 0) {
			col = 2;
			n = expl_dn_nid.size() & 1 ? 0 : 1;
		}
		QWidget::setTabOrder(old, edit);
		old = edit;
	}

	// Setup Request Attributes
	if (attrWidget->layout())
		delete attrWidget->layout();
	QGridLayout *attrLayout = new QGridLayout(attrWidget);
	attrLayout->setAlignment(Qt::AlignTop);
	attrLayout->setSpacing(6);
	attrLayout->setMargin(0);
	old = reqSubChange;
	n = 0;
	foreach(int nid, attr_nid) {
		DoubleClickLabel *label;
		QLineEdit *edit;
		QString trans = dn_translations[nid];

		label = new DoubleClickLabel(this);
		if (translate_dn && !trans.isEmpty()) {
			label->setText(trans);
			label->setToolTip(QString(OBJ_nid2sn(nid)));
		} else {
			label->setText(QString(OBJ_nid2ln(nid)));
			label->setToolTip(trans);
		}
		label->setClickText(OBJ_nid2sn(nid));
		connect(label, SIGNAL(doubleClicked(QString)),
                        MainWindow::getResolver(), SLOT(searchOid(QString)));
		edit = new QLineEdit(this);
		attrEdits << nameEdit(nid, edit, label);
		setupLineEditByNid(nid, edit);

		attrLayout->addWidget(label, n, 0);
		attrLayout->addWidget(edit, n, 1);

		QWidget::setTabOrder(old, edit);
		old = edit;
		n++;
	}
	// last polish
	on_certList_currentIndexChanged(0);
	certList->setDisabled(true);
	tabWidget->setCurrentIndex(0);
	attrWidget->hide();
	pt = none;
	notAfter->setEndDate(true);

	QMap<int, DoubleClickLabel*> nidLabel;
	nidLabel[NID_subject_alt_name] = sanLbl;
	nidLabel[NID_issuer_alt_name] = ianLbl;
	nidLabel[NID_crl_distribution_points] = crldpLbl;
	nidLabel[NID_info_access] = aiaLbl;
	nidLabel[NID_netscape_base_url] = nsBaseLbl;
	nidLabel[NID_netscape_revocation_url] = nsRevLbl;
	nidLabel[NID_netscape_ca_revocation_url] = nsCaRevLbl;
	nidLabel[NID_netscape_renewal_url] = nsRenewLbl;
	nidLabel[NID_netscape_ca_policy_url] = nsCaPolicyLbl;
	nidLabel[NID_netscape_ssl_server_name] = nsSslServerLbl;
	nidLabel[NID_netscape_comment] = nsCommentLbl;

	foreach(int nid, nidLabel.keys()) {
		DoubleClickLabel *l = nidLabel[nid];
		l->setText(translate_dn ?
			dn_translations[nid] : OBJ_nid2ln(nid));
		if (l->toolTip().isEmpty()) {
			l->setToolTip(translate_dn ?
				OBJ_nid2ln(nid) : dn_translations[nid]);
		}
		l->setClickText(OBJ_nid2sn(nid));
		connect(l, SIGNAL(doubleClicked(QString)),
                        MainWindow::getResolver(), SLOT(searchOid(QString)));
	}

	QMap<int, QGroupBox*> nidGroupBox;
	nidGroupBox[NID_basic_constraints] = bcBox;
	nidGroupBox[NID_key_usage] = kuBox;
	nidGroupBox[NID_ext_key_usage] = ekuBox;
	nidGroupBox[NID_netscape_cert_type] = nsCertTypeBox;

	foreach(int nid, nidGroupBox.keys()) {
		QGroupBox *g = nidGroupBox[nid];
		g->setTitle(translate_dn ?
			dn_translations[nid] : OBJ_nid2ln(nid));
		if (g->toolTip().isEmpty()) {
			g->setToolTip(translate_dn ?
				OBJ_nid2ln(nid) : dn_translations[nid]);
		}
	}

	if (translate_dn) {
		QList<QGroupBox*> gb;
		gb << distNameBox << keyIdentBox;
		foreach(QGroupBox *g, gb) {
			QString tt = g->toolTip();
			g->setToolTip(g->title());
			g->setTitle(tt);
		}
		QList<QCheckBox*> cbList;
		cbList << bcCritical << kuCritical << ekuCritical;
		foreach(QCheckBox* cb, cbList) {
			cb->setText(tr("Critical"));
		}
	}
	if (pki_x509::disable_netscape)
		tabWidget->removeTab(4);
}

void NewX509::setRequest()
{
	reqWidget->hide();
	attrWidget->show();

	signerBox->setEnabled(false);
	timewidget->setEnabled(false);
	capt->setText(tr("Create Certificate signing request"));
	authKey->setEnabled(false);
	setImage(MainWindow::csrImg);
	pt = x509_req;
}

NewX509::~NewX509()
{
	if (ctx_cert)
		delete(ctx_cert);
}

void NewX509::setupExtDNwidget(const QString &s, QLineEdit *l)
{
	setupLineEditByNid(OBJ_txt2nid(CCHAR(s)), l);
}

void NewX509::setupLineEditByNid(int nid, QLineEdit *l)
{
	ASN1_STRING_TABLE *tab = ASN1_STRING_TABLE_get(nid);
	QValidator *validator = NULL;
	QStringList info;

	info << QString("[%1]").arg(OBJ_nid2sn(nid));

	if (tab) {
		if (tab->minsize > 1)
			info << tr("minimum size: %1").arg(tab->minsize);
		if (tab->maxsize != -1)
			info << tr("maximum size: %1").arg(tab->maxsize);
		if (tab->mask == B_ASN1_PRINTABLESTRING) {
			info << tr("only a-z A-Z 0-9 '()+,-./:=?");
			QRegExp rx("[a-zA-Z0-9'()+,-./:=?]+");
			validator = new QRegExpValidator(rx, this);
		} else if (tab->mask == B_ASN1_IA5STRING) {
			info << tr("only 7-bit clean characters");
		}
	}
	l->setToolTip(info.join(" "));
	l->setValidator(validator);
}

void NewX509::getReqAttributes(pki_x509req *req)
{
	foreach(nameEdit e, attrEdits) {
		req->addAttribute(e.nid, e.edit->text());
	}
}

void NewX509::setReqAttributes(pki_x509req *req)
{
	foreach(nameEdit e, attrEdits) {
		e.edit->setText(req->getAttribute(e.nid));
	}
}

/* Initialize dialog for Template creation */
void NewX509::setTemp(pki_temp *temp)
{
	QString text = tr("Create XCA template");
	if (temp->getIntName() != "--") {
		description->setText(temp->getIntName());
		description->setDisabled(true);
		text = tr("Edit XCA template");
	}
	capt->setText(text);
	tabWidget->removeTab(0);
	privKeyBox->setEnabled(false);
	validityBox->setEnabled(false);
	setImage(MainWindow::tempImg);
	pt = tmpl;
}

/* Initialize dialog for Certificate creation */
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

/* Select a template and apply it */
void NewX509::defineTemplate(pki_temp *temp)
{
	fromTemplate(temp);
	templateChanged(temp);
}

/* Select a Request for signing it */
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

/* Preset all values from another request to create a aimilar one */
void NewX509::fromX509super(pki_x509super *cert_or_req)
{
	pki_temp *temp = new pki_temp("");
	temp->fromCert(cert_or_req);
	defineTemplate(temp);
	delete temp;

	description->setText(cert_or_req->getIntName());
	pki_key *key = cert_or_req->getRefKey();
	if (key) {
		usedKeysToo->setChecked(true);
		keyList->setCurrentIndex(private_keys.indexOf(
			key->getIntNameWithType()));
	}
	hashAlgo->setCurrentMD(cert_or_req->getDigest());

	switch(cert_or_req->getType()) {
	case x509: {
		pki_x509 *cert = (pki_x509*)cert_or_req;
		pki_x509 *signer = cert->getSigner();
		if (signer == cert) {
			foreignSignRB->setChecked(false);
		} else if (signer) {
			defineSigner(signer);
		}
		notBefore->setDate(cert->getNotBefore());
		notAfter->setDate(cert->getNotAfter());
		break;
	}
	case x509_req: {
		pki_x509req *req = (pki_x509req*)cert_or_req;
		setReqAttributes(req);
		break;
	}
	default:
		break;
	}

}

/* Preset all values from another cert to create a aimilar one */
void NewX509::defineCert(pki_x509 *cert)
{
	fromX509super(cert);

	pki_x509 *signer = cert->getSigner();
	if (signer == cert) {
		foreignSignRB->setChecked(false);
	} else if (signer) {
		defineSigner(signer);
	}
	notBefore->setDate(cert->getNotBefore());
	notAfter->setDate(cert->getNotAfter());
}

/* Preset the signing certificate */
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
		if (!defcert->getTemplate().isEmpty()) {
			on_applyTemplate_clicked();
		}
	}
}


static int lb2int(QListWidget *lb)
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

static void int2lb(QListWidget *lb, int x)
{
	int i, c=lb->count();
	QListWidgetItem *item;

	for (i=0; i<c; i++) {
		item = lb->item(i);
		lb->setItemSelected(item, (1<<i) & x);
	}
}

static void QString2lb(QListWidget *lb, QString x)
{
	QStringList li = x.split(", ");
	QList<QListWidgetItem *> items;

	for (int i=0; i<li.size(); i++) {
		QString lname = OBJ_sn2ln(CCHAR(li[i]));
		items = lb->findItems(lname, Qt::MatchExactly);
		if (items.size() > 0)
			lb->setItemSelected(items[0], 1);
	}
}

static QString lb2QString(QListWidget *lb)
{
	QStringList sl;

	for (int i=0; i<lb->count(); i++) {
		QListWidgetItem *item = lb->item(i);
		if (lb->isItemSelected(item)) {
			sl << QString(OBJ_ln2sn(CCHAR(item->text())));
		}
	}
	return sl.join(", ");
}

void NewX509::subjectFromTemplate(pki_temp *temp)
{
	if (temp)
		setX509name(temp->xname);
}

void NewX509::extensionsFromTemplate(pki_temp *temp)
{
	if (!temp)
		return;
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
	int2lb(nsCertType, temp->nsCertType);
	basicCA->setCurrentIndex(temp->ca);
	bcCritical->setChecked(temp->bcCrit);
	kuCritical->setChecked(temp->keyUseCrit);
	ekuCritical->setChecked(temp->eKeyUseCrit);
	subKey->setChecked(temp->subKey);
	authKey->setChecked(temp->authKey);
	int2lb(keyUsage, temp->keyUse);
	QString2lb(ekeyUsage, temp->eKeyUse);
	validNumber->setText(QString::number(temp->validN));
	validRange->setCurrentIndex(temp->validM);
	midnightCB->setChecked(temp->validMidn);
	basicPath->setText(temp->pathLen);
	nconf_data->document()->setPlainText(temp->adv_ext);
	noWellDefinedExpDate->setChecked(temp->noWellDefined);
	on_applyTime_clicked();
}

void NewX509::fromTemplate(pki_temp *temp)
{
	subjectFromTemplate(temp);
	extensionsFromTemplate(temp);
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
	temp->eKeyUse = lb2QString(ekeyUsage);
	temp->validN = validNumber->text().toInt();
	temp->validM = validRange->currentIndex();
	temp->pathLen = basicPath->text();
	if (!temp->pathLen.isEmpty())
		temp->pathLen = QString::number(temp->pathLen.toInt());
	temp->validMidn = midnightCB->isChecked();
	if (nconf_data->isReadOnly()) {
		temp->adv_ext = v3ext_backup;
	} else {
		temp->adv_ext = nconf_data->toPlainText();
	}
	temp->noWellDefined = noWellDefinedExpDate->isChecked();
}

void NewX509::on_fromReqCB_clicked()
{
	bool request = fromReqCB->isChecked();
	bool subj_tab_present = tabWidget->widget(1) == tab_1;
	bool subChange = reqSubChange->isChecked();

	if (request && subj_tab_present && !subChange)
		tabWidget->removeTab(1);
	else if ((!request || subChange) && !subj_tab_present)
		tabWidget->insertTab(1, tab_1, tr("Subject"));

	reqList->setEnabled(request);
	copyReqExtCB->setEnabled(request);
	showReqBut->setEnabled(request);
	reqSubChange->setEnabled(request);
	switchHashAlgo();
}

void NewX509::on_reqSubChange_clicked()
{
	if (reqSubChange->isChecked()) {
		pki_x509req *req = getSelectedReq();
		description->setText(req->getIntName());
		setX509name(req->getSubject());
		usedKeysToo->setEnabled(false);
		keyList->setEnabled(false);
		genKeyBut->setEnabled(false);
	}
	on_fromReqCB_clicked();
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

	if (key) {
		hashAlgo->setKeyType(key->getKeyType());
		hashAlgo->setupHashes(key->possibleHashNids());
	} else {
		hashAlgo->setKeyType(EVP_PKEY_RSA);
		hashAlgo->setupAllHashes();
	}
}

void NewX509::on_showReqBut_clicked()
{
	QString req = reqList->currentText();
	emit showReq(req);
}

void NewX509::on_genKeyBut_clicked()
{
	QString name = description->text();
	if (name.isEmpty())
		name = dnEntryByNid(NID_commonName);
	if (name.isEmpty())
		name = dnEntryByNid(NID_pkcs9_emailAddress);
	emit genKey(name);
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

pki_temp *NewX509::currentTemplate()
{
	if (!tempList->isEnabled())
		return NULL;
	QString name = tempList->currentText();
	if (name.isEmpty())
		return NULL;
	return (pki_temp *)MainWindow::temps->getByName(name);
}

void NewX509::on_applyTemplate_clicked()
{
	fromTemplate(currentTemplate());
}

void NewX509::on_applySubject_clicked()
{
	subjectFromTemplate(currentTemplate());
}

void NewX509::on_applyExtensions_clicked()
{
	extensionsFromTemplate(currentTemplate());
}

void NewX509::on_foreignSignRB_toggled(bool)
{
	switchHashAlgo();
}

void NewX509::newKeyDone(QString name)
{
	QStringList keys;
	private_keys = MainWindow::keys->get0KeyDesc(true);
	private_keys0 = MainWindow::keys->get0KeyDesc(false);
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
		foreach(nameEdit ne, nameEdits) {
			x.addEntryByNid(ne.nid, ne.edit->text());
		}
		row = extDNlist->rowCount();
		for (j=0; j<row; j++) {
			QStringList l = extDNlist->getRow(j);
			nid = OBJ_txt2nid(CCHAR(l[0]));
			x.addEntryByNid(nid, l[1]);
		}
	} catch (errorEx &err) {
		if (!err.isEmpty()) {
			if (_throw)
				throw err;
			else
				XCA_WARN(err.getString());
		}
	}
	return x;
}

QString NewX509::dnEntryByNid(int nid)
{
	foreach(nameEdit ne, nameEdits) {
		if (ne.nid == nid && !ne.edit->text().isEmpty())
			return ne.edit->text();
	}
	for (int j=0; j<extDNlist->rowCount(); j++) {
		QStringList l = extDNlist->getRow(j);
	        if (OBJ_txt2nid(CCHAR(l[0])) == nid && !l[1].isEmpty())
			return l[1];
	}
	return QString();
}

void NewX509::setX509name(const x509name &n)
{
	extDNlist->deleteAllRows();
	foreach(nameEdit ne, nameEdits) {
		ne.edit->setText("");
	}
	for (int i=0; i< n.entryCount(); i++) {
		int nid = n.nid(i);
		bool done = false;
		QStringList sl = n.entryList(i);
		foreach(nameEdit ne, nameEdits) {
			if (nid == ne.nid && ne.edit->text().isEmpty()) {
				ne.edit->setText(sl[2]);
				done = true;
				break;
			}
		}
		if (!done) {
			extDNlist->addRow(sl.mid(1, 2));
		}
	}
}

void NewX509::on_applyTime_clicked()
{
	notAfter->setDiff(notBefore, validNumber->text().toInt(),
				     validRange->currentIndex());
}

void NewX509::setupTmpCtx()
{
	pki_x509 *signcert;
	pki_x509req *req = NULL;
	pki_key *key = NULL;
	a1int serial;
	QString errtxt;

	// initially create temporary ctx cert
	if (ctx_cert)
		delete(ctx_cert);
	ctx_cert = new pki_x509();
	if (fromReqCB->isChecked()) {
		req = getSelectedReq();
		ctx_cert->setSubject(req->getSubject());
		if (req)
			key = req->getRefKey();
	} else {
		ctx_cert->setSubject(getX509name());
		key = getSelectedKey();
	}
	if (key)
		ctx_cert->setPubKey(key);
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
}

void NewX509::editV3ext(QLineEdit *le, QString types, int n)
{
	v3ext *dlg;

	dlg = new v3ext(this);
	setupTmpCtx();
	if (n == NID_info_access) {
		int nid, idx = aiaOid->currentIndex();
		if (idx >= 0 && idx < aia_nid.size()) {
			nid = aia_nid[idx];
			dlg->setPrefix(QString(OBJ_nid2sn(nid)) + ";");
		}
	}
	dlg->addInfo(le, types.split(',' ), n, &ext_ctx);
	dlg->exec();
	delete(dlg);
}

void NewX509::on_adv_validate_clicked()
{
	if (!nconf_data->isReadOnly()) {
		/* switch from edit to display mode */
		do_validateExtensions();
	} else {
		/* switch back to edit mode */
		undo_validateExtensions();
	}
}

void NewX509::checkIcon(const QString &text, int nid, QLabel *img)
{
	if (text.isEmpty()) {
		img->clear();
		return;
	}
	ign_openssl_error();
	switch (nid) {
	case NID_subject_alt_name:
		getSubAltName();
		break;
	case NID_issuer_alt_name:
		getIssAltName();
		break;
	case NID_crl_distribution_points:
		getCrlDist();
		break;
	case NID_info_access:
		getAuthInfAcc();
		break;
	}
	if (ign_openssl_error()) {
		img->setPixmap(*MainWindow::warnIco);
		return;
	}
	img->setPixmap(*MainWindow::doneIco);
}

void NewX509::checkSubAltName(const QString & text)
{
	checkIcon(text, NID_subject_alt_name, subAltIco);
}

void NewX509::checkIssAltName(const QString & text)
{
	checkIcon(text, NID_issuer_alt_name, issAltIco);
}

void NewX509::checkCrlDist(const QString & text)
{
	checkIcon(text, NID_crl_distribution_points, crlDistIco);
}

void NewX509::checkAuthInfAcc(const QString & text)
{
	checkIcon(text, NID_info_access, authInfAccIco);
}

int NewX509::do_validateExtensions()
{
	QString result;
	int ret = 0;

	if (!nconf_data->isReadOnly()) {
		v3ext_backup = nconf_data->toPlainText();
	}
	ret = validateExtensions(v3ext_backup, result);
	nconf_data->document()->setHtml(result);
	nconf_data->setReadOnly(true);
	adv_validate->setText(tr("Edit"));
	return ret;
}

void NewX509::undo_validateExtensions()
{
	if (nconf_data->isReadOnly()) {
		nconf_data->document()->setPlainText(v3ext_backup);
	}
	nconf_data->setReadOnly(false);
	adv_validate->setText(tr("Validate"));
}

int NewX509::validateExtensions(QString nconf, QString &result)
{
	int ret = 0;
	QStringList errors;
	extList el, req_el;
	ign_openssl_error();
	setupTmpCtx();
	(void)nconf;
	try {
		el = getGuiExt();
		if (!pki_x509::disable_netscape)
			el += getNetscapeExt();
		el.delInvalid();
	} catch (errorEx &err) {
		errors += err.getString();
		el.clear();
	}
	if (el.size() > 0) {
		result += "<h2><center>";
		result += tr("Other Tabs") + "</center></h2><p>\n";
		result += el.getHtml("<br>");
	}
	try {
		el = getAdvanced();
	} catch (errorEx &err) {
		errors += err.getString();
		el.clear();
	}
	if (el.size() > 0) {
		if (!result.isEmpty())
			result += "\n<hr>\n";
		result += "<h2><center>";
		result += tr("Advanced Tab") + "</center></h2><p>\n";
		result += el.getHtml("<br>");
	}
	if (errors.size()) {
		if (!result.isEmpty())
			result += "\n<hr>\n";
		result += "<h2><center>";
		result += tr("Errors") + "</center></h2><p><ul><li>\n";
		result += errors.join("</li><li>\n");
		result += "</li></ul>";
		ret = 1;
	}
	el.clear();
	if (fromReqCB->isChecked() && copyReqExtCB->isChecked()) {
		req_el = getSelectedReq()->getV3ext();
                for (int i=0; i<req_el.count(); i++) {
			if (ctx_cert && ctx_cert->addV3ext(req_el[i], true))
				el += req_el[i];
		}
	}
	if (el.size() > 0) {
		if (!result.isEmpty())
			result += "\n<hr>\n";
		result += "<h2><center>";
		result += tr("From PKCS#10 request") +"</center></h2><p>\n";
		result += el.getHtml("<br>");
	}
	el = getExtDuplicates();
	if (el.size() > 0) {
		QString errtxt;
		ret = 1;
		errtxt = "<h2><center><font color=\"red\">Error:</font>"
			"duplicate extensions:</center></h2><p><ul>\n";
		for(int i = 0; i< el.size(); i++) {
			errtxt += "<li>" +el[i].getObject() +"</li>\n";
		}
		errtxt += "</ul>\n<hr>\n";
		result = errtxt + result;
	}
	ign_openssl_error();
	return ret;
}

void NewX509::on_editSubAlt_clicked()
{
	QString s = "URI,email,RID,DNS,IP,otherName";
	editV3ext(subAltName, s, NID_subject_alt_name);
}

void NewX509::on_editIssAlt_clicked()
{
	QString s = "URI,email,RID,DNS,IP,otherName,issuer";
	editV3ext(issAltName, s, NID_issuer_alt_name);
}

void NewX509::on_editCrlDist_clicked()
{
	editV3ext(crlDist, "URI", NID_crl_distribution_points);
}

void NewX509::on_editAuthInfAcc_clicked()
{
	editV3ext(authInfAcc, "URI,email,RID,DNS,IP", NID_info_access);
}

void NewX509::on_tabWidget_currentChanged(int tab)
{
	if (tabWidget->tabText(tab) == tabnames[5])
		do_validateExtensions();
}

QString NewX509::mandatoryDnRemain()
{
	QStringList dnl = MainWindow::mandatory_dn.split(",");
	x509name n;
	int i;

	if (fromReqCB->isChecked() && !reqSubChange->isChecked())
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

void NewX509::gotoTab(int tab)
{
	for (int i=0; i<tabWidget->count(); i++) {
		if (tabWidget->tabText(i) == tabnames[tab]) {
			tabWidget->setCurrentIndex(i);
			break;
		}
	}
}

void NewX509::accept()
{
	x509name xn;
	on_tabWidget_currentChanged(0);
	try {
		xn = getX509name(1);
	} catch (errorEx &err) {
		gotoTab(1);
		xcaWarning msg(this, err.getString());
		msg.addButton(QMessageBox::Ok);
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		if (msg.exec() == QMessageBox::Close) {
			reject();
		}
		return;
	}
	QString lenErr = xn.checkLength();
	if (!lenErr.isEmpty()) {
		gotoTab(1);
		lenErr = tr("The following length restrictions of RFC3280 are violated:") +
			"\n" + lenErr;
		xcaWarning msg(this, lenErr);
		msg.addButton(QMessageBox::Ok)->setText(tr("Edit subject"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply)->setText(tr("Continue rollout"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
		}
	}
	if (fromReqCB->isChecked() && !getSelectedReq()->verify()) {
		gotoTab(0);
		xcaWarning msg(this,
			tr("The verification of the Certificate request failed.\nThe rollout should be aborted."));
		msg.addButton(QMessageBox::Ok)->setText(tr("Continue anyway"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		if (msg.exec() == QMessageBox::Close) {
			reject();
		}
	}
	if (description->text().isEmpty() && !fromReqCB->isChecked()) {
		QString cn = dnEntryByNid(NID_commonName);
		if (cn.isEmpty()) {
			gotoTab(1);
			xcaWarning msg(this,
				tr("The internal name and the common name are empty.\nPlease set at least the internal name."));
			msg.addButton(QMessageBox::Ok)->setText(tr("Edit name"));
			msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
			if (msg.exec() == QMessageBox::Close) {
				reject();
			}
			return;
		} else {
			description->setText(cn);
		}
	}
	if (keyList->count() == 0 && keyList->isEnabled() &&
				!fromReqCB->isChecked())
	{
		gotoTab(1);
		xcaWarning msg(this,
			tr("There is no Key selected for signing."));
		msg.addButton(QMessageBox::Ok)->setText(tr("Select key"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		if (msg.exec() == QMessageBox::Close) {
			reject();
		}
		return;
	}
	QString unsetDN;
	if (pt != tmpl)
		unsetDN = mandatoryDnRemain();
	if (!unsetDN.isEmpty()) {
		gotoTab(1);
		QString text = tr("The following distinguished name entries are empty:\n%1\nthough you have declared them as mandatory in the options menu.").arg(unsetDN);
		xcaWarning msg(this, text);
		msg.addButton(QMessageBox::Ok)->setText(tr("Edit subject"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply)->setText(tr("Continue rollout"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
		}
	}
	pki_key *signkey = NULL;
	pki_x509 *signer = NULL;
	if (foreignSignRB->isChecked()) {
		signer = getSelectedSigner();
		if (signer)
			signkey = signer->getRefKey();
	} else if (fromReqCB->isChecked()) {
		pki_x509req *req = getSelectedReq();
		if (req)
			signkey = req->getRefKey();
	} else {
		signkey = getSelectedKey();
	}
	if ((!signkey || signkey->isPubKey()) && pt != tmpl) {
		QString txt;
		gotoTab(signer ? 0 : 1);
		xcaWarning msg(this,
			tr("The key you selected for signing is not a private one."));
		txt = signer ? tr("Select other signer"):tr("Select other key");
		msg.addButton(QMessageBox::Ok)->setText(txt);
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		if (msg.exec() == QMessageBox::Close) {
			reject();
		}
		return;
        }
	if (signer && notBefore->getDate() < signer->getNotBefore()) {
		gotoTab(2);
		QString text = tr("The certificate will be earlier valid than the signer. This is probably not what you want.");
		xcaWarning msg(this, text);
		msg.addButton(QMessageBox::Ok)->setText(tr("Edit dates"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply)->setText(tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes)->setText(tr("Adjust date and continue"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
			case QMessageBox::Yes:
				notBefore->setDate(signer->getNotBefore());
		}
	}
	if (signer && notAfter->getDate() > signer->getNotAfter() &&
				!noWellDefinedExpDate->isChecked()) {
		gotoTab(2);
		QString text = tr("The certificate will be longer valid than the signer. This is probably not what you want.");
		xcaWarning msg(this, text);
		msg.addButton(QMessageBox::Ok)->setText(tr("Edit dates"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply)->setText(tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes)->setText(tr("Adjust date and continue"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
			case QMessageBox::Yes:
				notAfter->setDate(signer->getNotAfter());
		}
	}
	if (validityBox->isEnabled() &&
	    notBefore->getDate() > notAfter->getDate()) {
		gotoTab(2);
		QString text = tr("The certificate will be out of date before it becomes valid. You most probably mixed up both dates.");
		xcaWarning msg(this, text);
		msg.addButton(QMessageBox::Ok)->setText(tr("Edit dates"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply)->setText(tr("Continue rollout"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
		}
	}
	if (do_validateExtensions()) {
		gotoTab(5);
		QString text = tr("The certificate contains invalid or duplicate extensions. Check the validation on the advanced tab.");
		xcaWarning msg(this, text);
		msg.addButton(QMessageBox::Ok)->setText(tr("Edit extensions"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply)->setText(tr("Continue rollout"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
		}
	}
	QDialog::accept();
}
