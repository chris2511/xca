/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
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
#include <QPushButton>
#include <QPixmap>
#include <QPushButton>
#include <QValidator>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QMap>
#include <QPair>

#include "XcaWarning.h"
#include "NewKey.h"
#include "CertDetail.h"
#include "OidResolver.h"
#include "MainWindow.h"
#include "Help.h"
#include "v3ext.h"
#include "lib/x509name.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/oid.h"
#include "lib/func.h"
#include "lib/pki_evp.h"

void NewX509::setupExplicitDN(NIDlist my_dn_nid = NIDlist())
{
	NIDlist expl_dn_nid;

	/* Create configured explicit_dn list */
	if (!Settings["explicit_dn"].empty()) {
		foreach(QString dn, Settings["explicit_dn"].split(",")) {
			int nid = OBJ_sn2nid(CCHAR(dn));
			if (!my_dn_nid.contains(nid))
				expl_dn_nid << nid;
		}
	}
	nameEdits = setupExplicitInputs(my_dn_nid + expl_dn_nid,
					dnWidget, description, 2);
}

QList<nameEdit> NewX509::setupExplicitInputs(NIDlist nid_list,
			QWidget *parent, QWidget *old, int columns)
{
	QList<nameEdit> edits;
	QGridLayout *layout = dynamic_cast<QGridLayout *>(parent->layout());
	if (layout) {
		QLayoutItem *child;
		while ((child = layout->takeAt(0))) {
			delete child->widget();
			delete child;
		}
	} else {
		layout = new QGridLayout(parent);
		layout->setAlignment(Qt::AlignTop);
		layout->setSpacing(6);
		layout->setContentsMargins(0, 0, 0, 0);
		layout->setContentsMargins(11, 11, 11, 11);
	}
	int n = 0, col = 0;

	foreach(int nid, nid_list) {
		DoubleClickLabel *label;
		QLineEdit *edit;
		QString trans = dn_translations[nid];
		QString ln = OBJ_nid2ln(nid), sn = OBJ_nid2sn(nid);
		label = new DoubleClickLabel(parent);
		if (Settings["translate_dn"] && !trans.isEmpty()) {
			label->setText(trans);
			label->setToolTip(QString("[%1] %2").arg(sn, ln));
			if (sn == ln)
				label->setToolTip(ln);
		} else {
			label->setText(ln);
			label->setToolTip(QString("[%1] %2").arg(sn, trans));
			if (trans == sn)
				label->setToolTip(trans);
		}
		label->setClickText(OBJ_nid2sn(nid));
		connect(label, SIGNAL(doubleClicked(QString)),
		        MainWindow::getResolver(), SLOT(searchOid(QString)));
		edit = new QLineEdit(parent);
		setupLineEditByNid(nid, edit);
		edits << nameEdit(nid, edit, label);

		layout->addWidget(label, n, col);
		layout->addWidget(edit, n, col +1);
		n++;
		if (n > (nid_list.size()-1)/columns) {
			col += 2;
			n = 0;
		}
		QWidget::setTabOrder(old, edit);
		old = edit;
	}
	return edits;
}

NewX509::NewX509(QWidget *w) : XcaDetail(w)
{
	QStringList keys;
	db_key *keymodel = Database.model<db_key>();
	db_x509req *reqmodel = Database.model<db_x509req>();

	attr_nid << NID_pkcs9_unstructuredName << NID_pkcs9_challengePassword;

	setupUi(this);
	mainwin->helpdlg->register_ctxhelp_button(this, "wizard");

	/* temporary storage for creating temporary X509V3_CTX */
	foreach(int nid, distname_nid)
		keys << QString(OBJ_nid2ln(nid));

	tabnames = QStringList({
		"wizard_src", "wizard_subject", "wizard_extensions",
		"wizard_keyusage", "wizard_netscape", "wizard_advanced",
		"wizard_comment"});
	extDNlist->setKeys(keys);
	extDNlist->setInfoLabel(extDNinfo);
	connect(extDNlist->itemDelegateForColumn(1),
		SIGNAL(setupLineEdit(const QString &, QLineEdit *)),
		       this, SLOT(setupExtDNwidget(const QString &, QLineEdit *)));
	connect(nameCons, SIGNAL(textChanged(const QString &)),
	        this, SLOT(checkNameConstraints(const QString &)));
	connect(subAltName, SIGNAL(textChanged(const QString &)),
	        this, SLOT(checkSubAltName(const QString &)));
	connect(issAltName, SIGNAL(textChanged(const QString &)),
	        this, SLOT(checkIssAltName(const QString &)));
	connect(crlDist, SIGNAL(textChanged(const QString &)),
	        this, SLOT(checkCrlDist(const QString &)));
	connect(authInfAcc, SIGNAL(textChanged(const QString &)),
	        this, SLOT(checkAuthInfAcc(const QString &)));
	if (keymodel)
		connect(keymodel, SIGNAL(keyDone(pki_key*)),
			this, SLOT(newKeyDone(pki_key*)));
	if (reqmodel)
		connect(reqmodel, SIGNAL(pkiChanged(pki_base*)),
			this, SLOT(itemChanged(pki_base*)));

	setWindowTitle(XCA_TITLE);

	for (int i=0; i<tabWidget->count(); i++) {
		tabWidget->widget(i)->setObjectName(tabnames[i]);
		qDebug() << "TAB:" << i << tabWidget->tabText(i);
	}

	nsImg->setPixmap(QPixmap(":nsImg"));

	// are there any usable private keys  ?
	newKeyDone(NULL);

	// any PKCS#10 requests to be used ?
	QList<pki_x509req *> requests = getAllRequests();
	if (requests.isEmpty()) {
		fromReqCB->setDisabled(true);
		fromReqCB->setChecked(false);
	} else {
		reqList->insertPkiItems(requests);
	}
	on_fromReqCB_clicked();

	// How about signing certificates ?
	QList<pki_x509*> issuers = getAllIssuers();
	if (issuers.isEmpty()) {
		foreignSignRB->setDisabled(true);
	} else {
		certList->insertPkiItems(issuers);
	}

	// set dates to now and now + 1 year
	validN->setText("1");
	validRange->setCurrentIndex(2);
	on_applyTime_clicked();

	// settings for the templates ....
	tempList->insertPkiItems(getAllTempsAndPredefs());

	// setup Extended keyusage
	foreach(int nid, extkeyuse_nid)
		ekeyUsage->addItem(OBJ_nid2ln(nid));

	// init the X509 v3 context
	X509V3_set_ctx(&ext_ctx, NULL , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb(&ext_ctx);

	// Setup dnWidget
	setupExplicitDN();

	// Setup Request Attributes
	attrEdits = setupExplicitInputs(attr_nid, attrWidget, reqSubChange, 1);

	// last polish
	on_certList_currentIndexChanged(0);
	certList->setDisabled(true);
	tabWidget->setCurrentIndex(0);
	attrWidget->hide();
	notAfter->setEndDate(true);
	basicPath->setValidator(new QIntValidator(0, 1000, this));

	QMap<int, QWidget*> nidWidget;
	nidWidget[NID_name_constraints] = nameConsLbl;
	nidWidget[NID_subject_alt_name] = sanLbl;
	nidWidget[NID_issuer_alt_name] = ianLbl;
	nidWidget[NID_crl_distribution_points] = crldpLbl;
	nidWidget[NID_info_access] = aiaLbl;
	nidWidget[NID_netscape_base_url] = nsBaseLbl;
	nidWidget[NID_netscape_revocation_url] = nsRevLbl;
	nidWidget[NID_netscape_ca_revocation_url] = nsCaRevLbl;
	nidWidget[NID_netscape_renewal_url] = nsRenewLbl;
	nidWidget[NID_netscape_ca_policy_url] = nsCaPolicyLbl;
	nidWidget[NID_netscape_ssl_server_name] = nsSslServerLbl;
	nidWidget[NID_netscape_comment] = nsCommentLbl;

	nidWidget[NID_basic_constraints] = bcBox;
	nidWidget[NID_key_usage] = kuBox;
	nidWidget[NID_ext_key_usage] = ekuBox;
	nidWidget[NID_netscape_cert_type] = nsCertTypeBox;

	nidWidget[NID_subject_key_identifier] = subKey;
	nidWidget[NID_authority_key_identifier] = authKey;

	foreach(int nid, nidWidget.keys()) {
		QString text = OBJ_nid2ln(nid);
		QString tooltip = dn_translations[nid];
		QWidget *w = nidWidget[nid];
		QString tt = w->toolTip();

		if (Settings["translate_dn"])
			text.swap(tooltip);

		if (!tt.isEmpty())
			tooltip = QString("%1 (%2)").arg(tt).arg(tooltip);

		w->setToolTip(tooltip);

		DoubleClickLabel *l = dynamic_cast<DoubleClickLabel*>(w);
		QGroupBox *g = dynamic_cast<QGroupBox*>(w);
		QCheckBox *c = dynamic_cast<QCheckBox*>(w);
		if (l) {
			l->setText(text);
			l->setClickText(OBJ_nid2sn(nid));
			connect(l, SIGNAL(doubleClicked(QString)),
				MainWindow::getResolver(),
				SLOT(searchOid(QString)));
		} else if (g) {
			g->setTitle(text);
		} else if (c) {
			c->setText(text);
		}
	}

	if (Settings["translate_dn"]) {
		QList<QGroupBox*> gb { distNameBox, keyIdentBox };
		foreach(QGroupBox *g, gb) {
			QString tt = g->toolTip();
			g->setToolTip(g->title());
			g->setTitle(tt);
		}
		QList<QCheckBox*> cbList { bcCritical,kuCritical,ekuCritical };
		foreach(QCheckBox* cb, cbList) {
			cb->setText(tr("Critical"));
		}
	}
	if (Settings["disable_netscape"])
		tabWidget->removeTab(4);

	// Setup widget <-> Template mapping
#define MAP_LE(name) templateLineEdits[#name] = name;
	MAP_LE(nameCons);
	MAP_LE(subAltName);
	MAP_LE(issAltName);
	MAP_LE(crlDist);
	MAP_LE(authInfAcc);
	MAP_LE(nsComment);
	MAP_LE(nsBaseUrl);
	MAP_LE(nsRevocationUrl);
	MAP_LE(nsCARevocationUrl);
	MAP_LE(nsRenewalUrl);
	MAP_LE(nsCaPolicyUrl);
	MAP_LE(nsSslServerName);
	MAP_LE(validN);
	MAP_LE(basicPath);

#define MAP_CB(name) templateCheckBoxes[#name] = name;
	MAP_CB(bcCritical);
	MAP_CB(kuCritical);
	MAP_CB(ekuCritical);
	MAP_CB(subKey);
	MAP_CB(authKey);
	MAP_CB(OCSPstaple);
	MAP_CB(validMidn);
	MAP_CB(noWellDefinedExpDate);
}

void NewX509::setRequest()
{
	reqWidget->hide();
	attrWidget->show();

	signerBox->setEnabled(false);
	timewidget->setEnabled(false);
	capt->setText(tr("Create Certificate signing request"));
	authKey->setEnabled(false);
	image->setPixmap(QPixmap(":csrImg"));
	pt = x509_req;
}

NewX509::~NewX509()
{
	delete ctx_cert;
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
			QRegularExpression rx("[a-zA-Z0-9'()+,-./:=?]+");
			validator = new QRegularExpressionValidator(rx, this);
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
void NewX509::setTemp(pki_temp *temp, bool create)
{
	description->setText(temp->getIntName());
	capt->setText(tr("Edit XCA template"));
	tabWidget->removeTab(0);
	privKeyBox->setEnabled(false);
	validityBox->setEnabled(false);
	image->setPixmap(QPixmap(":tempImg"));
	pt = tmpl;
	fromTemplate(temp);
	comment->setPlainText(temp->getComment());
	if (!create)
		connect_pki(temp);
}

/* Initialize dialog for Certificate creation */
void NewX509::setCert()
{
	capt->setText(tr("Create x509 Certificate"));
	image->setPixmap(QPixmap(":certImg"));
	pt = x509;
}

/* Select a template and apply it */
void NewX509::defineTemplate(pki_temp *temp)
{
	fromTemplate(temp);
	templateChanged(temp);
	pkiSource = transformed;
}

/* Select a Request for signing it */
void NewX509::defineRequest(pki_x509req *req)
{
	fromReqCB->setEnabled(true);
	fromReqCB->setChecked(true);
	reqList->setCurrentPkiItem(req);
	pkiSource = transformed;
	on_fromReqCB_clicked();
}

/* Preset all values from another request to create a similar one */
void NewX509::fromX509super(pki_x509super *cert_or_req, bool applyTemp)
{
	pki_temp *temp = new pki_temp("");
	temp->fromCert(cert_or_req);
	defineTemplate(temp);
	delete temp;

	description->setText(cert_or_req->getIntName());
	pki_key *key = cert_or_req->getRefKey();
	if (key) {
		usedKeysToo->setChecked(true);
		keyList->setCurrentPkiItem(key);
	}
	hashAlgo->setCurrent(cert_or_req->getDigest());

	switch(cert_or_req->getType()) {
	case x509: {
		pki_x509 *cert = (pki_x509*)cert_or_req;
		pki_x509 *signer = cert->getSigner();
		if (signer == cert) {
			foreignSignRB->setChecked(false);
		} else if (signer) {
			defineSigner(signer, applyTemp);
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

pki_temp *NewX509::caTemplate(pki_x509 *ca) const
{
	QVariant sqlId = ca->getTemplateSqlId();
	if (!sqlId.isValid())
		return NULL;
	return Store.lookupPki<pki_temp>(sqlId);
}

/* Preset the signing certificate */
void NewX509::defineSigner(pki_x509 *defcert, bool applyTemp)
{
	// suggested from: Andrey Brindeew <abr@abr.pp.ru>
	if (defcert && defcert->canSign() ) {
		if (certList->setCurrentPkiItem(defcert) != -1) {
			foreignSignRB->setChecked(true);
			certList->setEnabled(true);
			if (applyTemp &&
			    defcert->getTemplateSqlId().isValid())
			{
				on_applyTemplate_clicked();
			}
		}
	}
}

static int lb2int(QListWidget *lb)
{
	int i, x=0, c=lb->count();

	for (i=0; i<c; i++) {
		if (lb->item(i)->isSelected())
			x |= 1<<i;
	}
	return x;
}

static void int2lb(QListWidget *lb, int x)
{
	for (int i=0; i<lb->count(); i++)
		lb->item(i)->setSelected((1<<i) & x);
}

static void QString2lb(QListWidget *lb, QString x)
{
	QStringList li = x.split(",");
	QList<QListWidgetItem *> items;

	for (int i=0; i<li.size(); i++) {
		QString lname = OBJ_sn2ln(CCHAR(li[i].trimmed()));
		items = lb->findItems(lname, Qt::MatchExactly);
		if (items.size() > 0)
			items[0]->setSelected(true);
	}
}

static QString lb2QString(QListWidget *lb)
{
	QStringList sl;

	for (int i=0; i<lb->count(); i++) {
		QListWidgetItem *item = lb->item(i);
		if (item->isSelected())
			sl << QString(OBJ_ln2sn(CCHAR(item->text())));
	}
	return sl.join(", ");
}

void NewX509::subjectFromTemplate(pki_temp *temp)
{
	if (temp)
		setX509name(temp->getSubject());
}


void NewX509::extensionsFromTemplate(pki_temp *temp)
{
	if (!temp)
		return;

	QMapIterator<QString, QLineEdit*> l(templateLineEdits);
	while (l.hasNext()) {
		l.next();
		qDebug() << "APPLY LineEdits" << l.key() << temp->getSetting(l.key());
		l.value()->setText(temp->getSetting(l.key()));
	}
	QMapIterator<QString, QCheckBox*> i(templateCheckBoxes);
	while (i.hasNext()) {
		i.next();
		i.value()->setChecked(temp->getSettingInt(i.key()));
	}
	int2lb(nsCertType, temp->getSettingInt("nsCertType"));
	basicCA->setCurrentIndex(temp->getSettingInt("ca"));
	int2lb(keyUsage, temp->getSettingInt("keyUse"));
	QString2lb(ekeyUsage, temp->getSetting("eKeyUse"));
	validRange->setCurrentIndex(temp->getSettingInt("validM"));
	nconf_data->document()->setPlainText(temp->getSetting("adv_ext"));

	on_applyTime_clicked();
}

void NewX509::fromTemplate(pki_temp *temp)
{
	subjectFromTemplate(temp);
	extensionsFromTemplate(temp);
}

void NewX509::updateNameComment()
{
	// If we display a template, import all changes to the template
	pki_temp *temp = dynamic_cast<pki_temp*>(pki);
	toTemplate(temp);
}

void NewX509::toTemplate(pki_temp *temp)
{
	if (!temp)
		return;
	temp->setIntName(description->text());
	temp->setSubject(getX509name());

	QMapIterator<QString, QLineEdit*> l(templateLineEdits);
	while (l.hasNext()) {
		l.next();
		temp->setSetting(l.key(), l.value()->text());
	}
	QMapIterator<QString, QCheckBox*> i(templateCheckBoxes);
	while (i.hasNext()) {
		i.next();
		temp->setSetting(i.key(), i.value()->isChecked());
	}

	temp->setSetting("nsCertType", lb2int(nsCertType));
	temp->setSetting("ca", basicCA->currentIndex());
	temp->setSetting("keyUse", lb2int(keyUsage));
	temp->setSetting("eKeyUse", lb2QString(ekeyUsage));
	temp->setSetting("validN", validN->text().toInt());
	temp->setSetting("validM", validRange->currentIndex());
	if (!temp->getSetting("basicPath").isEmpty())
		temp->setSetting("basicPath", temp->getSettingInt("basicPath"));
	if (nconf_data->isReadOnly()) {
		temp->setSetting("adv_ext", v3ext_backup);
	} else {
		temp->setSetting("adv_ext", nconf_data->toPlainText());
	}

	temp->setComment(comment->toPlainText());
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

void NewX509::on_keyList_currentIndexChanged(int)
{
	switchHashAlgo();
}

void NewX509::on_reqList_currentIndexChanged(int)
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

	if (key)
		hashAlgo->setupHashes(key->possibleHashNids());
	else
		hashAlgo->setupAllHashes();
}

void NewX509::on_showReqBut_clicked()
{
	CertDetail::showCert(this, reqList->currentPkiItem());
}

QList<pki_x509req *> NewX509::getAllRequests() const
{
	db_x509req *db = Database.model<db_x509req>();
	return db ? db->getAllRequests() : QList<pki_x509req *>();
}

QList<pki_x509*> NewX509::getAllIssuers() const
{
	db_x509 *db = Database.model<db_x509>();
	return db ? db->getAllIssuers() : QList<pki_x509*>();
}

QList<pki_temp*> NewX509::getAllTempsAndPredefs() const
{
	db_temp *db = Database.model<db_temp>();
	return db ? db->getPredefs() + Store.getAll<pki_temp>()
				: QList<pki_temp*>();
}

QList<pki_key*> NewX509::getAllKeys() const
{
	db_key *db = Database.model<db_key>();
	return db ? db->getAllKeys() : QList<pki_key*>();
}

QList<pki_key*> NewX509::getUnusedKeys() const
{
	db_key *db = Database.model<db_key>();
	return db ? db->getUnusedKeys() : QList<pki_key*>();
}

void NewX509::itemChanged(pki_base* req)
{
	reqList->insertPkiItems(getAllRequests());
	reqList->setCurrentPkiItem(dynamic_cast<pki_x509req*>(req));
}

void NewX509::on_genKeyBut_clicked()
{
	if (!Database.isOpen())
		return;
	QString name = description->text();
	if (name.isEmpty())
		name = getX509name().getMostPopular();

	NewKey *dlg = new NewKey(this, name);
	if (dlg->exec()) {
		db_key *keys = Database.model<db_key>();
		keys->newKey(dlg->getKeyJob(), dlg->keyDesc->text());
	}
	delete dlg;
}

void NewX509::on_certList_currentIndexChanged(int)
{
	a1time snb, sna;
	pki_x509 *cert = getSelectedSigner();

	switchHashAlgo();

	if (!cert)
		return;

	pki_temp *templ = caTemplate(cert);
	snb = cert->getNotBefore();
	sna = cert->getNotAfter();
	if (snb > notBefore->getDate())
		notBefore->setDate(snb);
	if (sna < notAfter->getDate())
		notAfter->setDate(sna);

	if (templ)
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
	tempList->setCurrentPkiItem(templ);
}

pki_temp *NewX509::currentTemplate()
{
	if (!tempList->isEnabled())
		return NULL;
	return tempList->currentPkiItem();
}

void NewX509::selfComment(QString msg)
{
	comment->setPlainText(appendXcaComment(comment->toPlainText(), msg));
}

void NewX509::on_applyTemplate_clicked()
{
	pki_temp *t = currentTemplate();
	if (!t)
		return;
	fromTemplate(t);
	selfComment(tr("Template '%1' applied").arg(t->comboText()));
}

void NewX509::on_applySubject_clicked()
{
	pki_temp *t = currentTemplate();
	subjectFromTemplate(t);
	selfComment(tr("Subject applied from template '%1'")
			.arg(t->comboText()));
}

void NewX509::on_applyExtensions_clicked()
{
	pki_temp *t = currentTemplate();
	extensionsFromTemplate(t);
	selfComment(tr("Extensions applied from template '%1'")
			.arg(t->comboText()));
}

void NewX509::on_foreignSignRB_toggled(bool)
{
	switchHashAlgo();
}

void NewX509::newKeyDone(pki_key *nkey)
{
	allKeys =   getAllKeys();
	unusedKeys = getUnusedKeys();
	on_usedKeysToo_toggled(true);
	if (nkey) {
		selfComment(tr("New key '%1' created")
				.arg(nkey->comboText()));
		keyList->setCurrentPkiItem(nkey);
	} else {
		keyList->setCurrentIndex(0);
	}
}

void NewX509::on_usedKeysToo_toggled(bool)
{
	pki_key *cur = keyList->currentPkiItem();
	keyList->clear();
	keyList->insertPkiItems(usedKeysToo->isChecked() ?
			allKeys : unusedKeys);
	keyList->setCurrentPkiItem(cur);
}

pki_key *NewX509::getSelectedKey()
{
	return keyList->currentPkiItem();
}

pki_x509 *NewX509::getSelectedSigner()
{
	return certList->currentPkiItem();
}

pki_x509req *NewX509::getSelectedReq()
{
	return reqList->currentPkiItem();
}

x509name NewX509::getX509name(int _throw)
{
	x509name x;
	int j, row, nid;

	if (fromReqCB->isChecked() && !reqSubChange->isChecked())
		return getSelectedReq()->getSubject();

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

void NewX509::setX509name(const x509name &n)
{
	extDNlist->deleteAllRows();
	foreach(nameEdit ne, nameEdits) {
		ne.edit->setText("");
	}

	if (Settings["adapt_explicit_subj"]) {
		NIDlist mydn;
		for (int i=0; i< n.entryCount(); i++)
			mydn << n.nid(i);
		setupExplicitDN(mydn);
	}
	for (int i=0, j=0; i< n.entryCount(); i++) {
		int nid = n.nid(i);
		bool done = false;
		QStringList sl = n.entryList(i);
		for ( ; j < nameEdits.size(); j++) {
			nameEdit ne(nameEdits[j]);
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
	notAfter->setDiff(notBefore, validN->text().toInt(),
				     validRange->currentIndex());
}

void NewX509::setupTmpCtx()
{
	pki_x509 *signcert;
	pki_x509req *req = NULL;
	pki_key *key = NULL;
	a1int serial(1);
	QString errtxt;

	// initially create temporary ctx cert
	delete ctx_cert;
	ctx_cert = new pki_x509();
	ctx_cert->setSubject(getX509name());
	if (fromReqCB->isChecked()) {
		req = getSelectedReq();
		if (req)
			key = req->getRefKey();
	} else {
		key = getSelectedKey();
	}
	if (key)
		ctx_cert->setPubKey(key);
	// Step 2 - select Signing
	if (foreignSignRB->isChecked()) {
		signcert = getSelectedSigner();
		ctx_cert->setIssuer(signcert->getSubject());
	} else {
		signcert = ctx_cert;
		ctx_cert->setIssuer(ctx_cert->getSubject());
	}
	ctx_cert->setSerial(serial);
	ctx_cert->setNotBefore(notBefore->getDate());
	ctx_cert->setNotAfter(notAfter->getDate());
	initCtx(ctx_cert, signcert, req);
}

void NewX509::editV3ext(QLineEdit *le, QString types, int n)
{
	v3ext *dlg;

	dlg = new v3ext(this);
	setupTmpCtx();
	dlg->addInfo(le, types.split(','), n, &ext_ctx);
	dlg->exec();
	delete dlg;
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
	x509v3ext ext;
	if (text.isEmpty()) {
		img->clear();
		return;
	}
	setupTmpCtx();
	ign_openssl_error();
	switch (nid) {
	case NID_name_constraints:
		ext = getNameConstraints();
		break;
	case NID_subject_alt_name:
		ext = getSubAltName();
		break;
	case NID_issuer_alt_name:
		ext = getIssAltName();
		break;
	case NID_crl_distribution_points:
		ext = getCrlDist();
		break;
	case NID_info_access:
		ext = getAuthInfAcc();
		break;
	}
	img->setPixmap(ext.isValid() ? QPixmap(":doneIco") : QPixmap(":warnIco"));
}

void NewX509::checkNameConstraints(const QString & text)
{
	checkIcon(text, NID_name_constraints, nameConsIco);
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

enum NewX509::extension_error NewX509::do_validateExtensions()
{
	QString result;
	extension_error ret;

	if (!nconf_data->isReadOnly()) {
		v3ext_backup = nconf_data->toPlainText();
	}
	ret = validateExtensions(result);
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

enum NewX509::extension_error NewX509::validateExtensions(QString &result)
{
	enum extension_error ee = ee_none;
	QStringList errors;
	extList el, el_all, req_el;
	ign_openssl_error();
	setupTmpCtx();

	try {
		el = getGuiExt();
		if (!Settings["disable_netscape"])
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
	setupTmpCtx();
	el_all += el;
	try {
		el = getAdvanced();
	} catch (errorEx &err) {
		errors += err.getString();
		el.clear();
	}
	el_all += el;
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
		ee = ee_invaldup;
	}
	el.clear();
	setupTmpCtx();
	if (fromReqCB->isChecked() && copyReqExtCB->isChecked()) {
		req_el = getSelectedReq()->getV3ext();
		for (int i=0; i<req_el.count(); i++) {
			if (ctx_cert && ctx_cert->addV3ext(req_el[i], true))
				el += req_el[i];
		}
	}
	el_all += el;
	if (el.size() > 0) {
		if (!result.isEmpty())
			result += "\n<hr>\n";
		result += "<h2><center>";
		result += tr("From PKCS#10 request") +"</center></h2><p>\n";
		result += el.getHtml("<br>");
	}
	el = getExtDuplicates(el_all);
	if (el.size() > 0) {
		QString errtxt;
		ee = ee_invaldup;
		errtxt = QString("<h2><center>"
					"<font color=\"red\">%1:</font> %2:"
				"</center></h2><p><ul>\n")
			.arg(tr("Error")).arg(tr("duplicate extensions"));
		for(int i = 0; i< el.size(); i++) {
			errtxt += "<li>" +el[i].getObject() +"</li>\n";
		}
		errtxt += "</ul>\n<hr>\n";
		result = errtxt + result;
	}
	QString lineext;
	if (!nameCons->text().isEmpty() && !getNameConstraints().isValid())
		lineext += tr("The Name Constraints are invalid") + "<br>\n";
	if (!subAltName->text().isEmpty() && !getSubAltName().isValid())
		lineext += tr("The Subject Alternative Name is invalid") + "<br>\n";
	if (!issAltName->text().isEmpty() && !getIssAltName().isValid())
		lineext += tr("The Issuer Alternative Name is invalid") + "<br>\n";
	if (!crlDist->text().isEmpty() && !getCrlDist().isValid())
		lineext += tr("The CRL Distribution Point is invalid") + "<br>\n";
	if (!authInfAcc->text().isEmpty() && !getAuthInfAcc().isValid())
		lineext += tr("The Authority Information Access is invalid") + "<br>\n";
	if (!lineext.isEmpty()) {
		if (!result.isEmpty())
			result += "\n<hr>\n";
		result += lineext;
		ee = ee_inval;
	}
	if (ee == ee_none && el_all.size() == 0 && pt == x509)
		ee = ee_empty;

	ign_openssl_error();
	return ee;
}

void NewX509::on_editNameCons_clicked()
{
	QStringList permut;
	for (const QString &group : QStringList { "permitted", "excluded" }) {
		for(const QString &type : QStringList { "URI", "email", "RID", "DNS", "IP", "UPN", "othername" }) {
			permut << QString("%1;%2").arg(group).arg(type);
		}
	}
	editV3ext(nameCons, permut.join(","), NID_name_constraints);
}

void NewX509::on_editSubAlt_clicked()
{
	QString s = "URI,email,RID,DNS,IP,UPN,otherName";
	editV3ext(subAltName, s, NID_subject_alt_name);
}

void NewX509::on_editIssAlt_clicked()
{
	QString s = "URI,email,RID,DNS,IP,UPN,otherName,issuer";
	editV3ext(issAltName, s, NID_issuer_alt_name);
}

void NewX509::on_editCrlDist_clicked()
{
	editV3ext(crlDist, "URI", NID_crl_distribution_points);
}

void NewX509::on_editAuthInfAcc_clicked()
{
	QStringList permut, groups { "OCSP", "caIssuers" },
			types{ "URI", "email", "RID", "DNS", "IP" };
	foreach(QString group, groups) {
		foreach(QString type, types) {
			permut << QString("%1;%2").arg(group).arg(type);
		}
	}
	editV3ext(authInfAcc, permut.join(","), NID_info_access);
}

void NewX509::on_tabWidget_currentChanged(int tab)
{
	QString tab_name = tabWidget->widget(tab)->objectName();
	if (tab_name == tabnames[5])
		do_validateExtensions();
	buttonBox->setProperty("help_ctx", QVariant(tab_name));
}

QString NewX509::mandatoryDnRemain()
{
	QStringList remain, dnl = QString(Settings["mandatory_dn"]).split(",");
	x509name n;
	int i;

	if (QString(Settings["mandatory_dn"]).isEmpty())
		return QString();

	n = getX509name();

	for (i=0; i< n.entryCount(); i++) {
		int j = dnl.indexOf(QString(OBJ_nid2sn(n.nid(i))));
		if (j>=0)
			dnl.removeAt(j);
	}
	if (dnl.size() == 0)
		return QString();

	foreach(QString x, dnl)
		remain << QString(OBJ_sn2ln(x.toLatin1()));
	return QString("'%1'").arg(remain.join("','"));
}

void NewX509::gotoTab(int tab)
{
	for (int i=0; i<tabWidget->count(); i++) {
		if (tabWidget->widget(i)->objectName() == tabnames[tab]) {
			tabWidget->setCurrentIndex(i);
			break;
		}
	}
}

enum pki_source NewX509::getPkiSource() const
{
	return pkiSource;
}

void NewX509::accept()
{
	x509name xn;
	on_tabWidget_currentChanged(0);
	try {
		xn = getX509name(1);
	} catch (errorEx &err) {
		gotoTab(1);
		xcaWarningBox msg(this, err.getString());
		msg.addButton(QMessageBox::Ok);
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
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
		xcaWarningBox msg(this, lenErr);
		msg.addButton(QMessageBox::Ok, tr("Edit subject"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
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
		xcaWarningBox msg(this,
			tr("The verification of the Certificate request failed.\nThe rollout should be aborted."));
		msg.addButton(QMessageBox::Ok, tr("Continue anyway"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		if (msg.exec() == QMessageBox::Close) {
			reject();
		}
	}
	if (description->text().isEmpty() && !fromReqCB->isChecked()) {
		QString cn = getX509name().getMostPopular();
		if (cn.isEmpty()) {
			gotoTab(1);
			xcaWarningBox msg(this,
				tr("The internal name and the common name are empty.\nPlease set at least the internal name."));
			msg.addButton(QMessageBox::Ok, tr("Edit name"));
			msg.addButton(QMessageBox::Close, tr("Abort rollout"));
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
		xcaWarningBox msg(this,
			tr("There is no Key selected for signing."));
		msg.addButton(QMessageBox::Ok, tr("Select key"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
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
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit subject"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
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
		xcaWarningBox msg(this,
			tr("The key you selected for signing is not a private one."));
		txt = signer ? tr("Select other signer"):tr("Select other key");
		msg.addButton(QMessageBox::Ok, txt);
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		if (msg.exec() == QMessageBox::Close) {
			reject();
		}
		return;
	}
	if (hashAlgo->count() > 0 && hashAlgo->current().isInsecure()) {
		gotoTab(0);
		xcaWarningBox msg(this, tr("The currently selected hash algorithm '%1' is insecure and should not be used.").arg(hashAlgo->current().name()));
		msg.addButton(QMessageBox::Ok, tr("Select other algorithm"));
		msg.addButton(QMessageBox::Yes, tr("Use algorithm anyway"));
		if (msg.exec() == QMessageBox::Ok)
			return;
	}
	if (signer && notBefore->getDate() < signer->getNotBefore()) {
		gotoTab(2);
		QString text = tr("The certificate will be earlier valid than the signer. This is probably not what you want.");
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit dates"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes, tr("Adjust date and continue"));
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
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit dates"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes, tr("Adjust date and continue"));
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
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit dates"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
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
	enum extension_error ee = do_validateExtensions();
	if (ee != ee_none) {
		QString text;
		switch (ee) {
		case ee_invaldup:
			text = tr("The certificate contains invalid or duplicate extensions. Check the validation on the advanced tab.");
			gotoTab(5);
			break;
		case ee_empty:
			text = tr("The certificate contains no extensions. You may apply the extensions of one of the templates to define the purpose of the certificate.");
			gotoTab(0);
			break;
		case ee_inval:
			text = tr("The certificate contains invalid extensions.");
			gotoTab(2);
			break;
		case ee_none:
			break;
		}
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit extensions"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
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
	QString cn = xn.getEntryByNid(NID_commonName);
	QStringList san = subAltName->text().split(QRegularExpression(" *, *"));
	if (cn.isEmpty() && san.contains("DNS:copycn") && pt != tmpl) {
		gotoTab(2);
		xcaWarningBox msg(this, tr("The subject alternative name shall contain a copy of the common name. However, the common name is empty."));
		msg.addButton(QMessageBox::Ok, tr("Edit extensions"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
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
	if (foreignSignRB->isChecked()) {
		setupTmpCtx();
		// Update SAN and BC of ctx_cert
		getBasicConstraints();
		getSubAltName();
		for (pki_x509 *crt = getSelectedSigner(), *oldcrt = nullptr;
			crt && crt != oldcrt;
			oldcrt = crt, crt = crt->getSigner())
		{
			int rc = ctx_cert->name_constraint_check(crt);
			qDebug() << ctx_cert->getIntName() << "Issuer"
			         << crt->getIntName()<< get_ossl_verify_error(rc);
			if (rc == X509_V_OK)
				continue;
			gotoTab(2);
			xcaWarningBox msg(this, tr("A name constraint of the issuer '%1' is violated: %2")
				.arg(crt->getIntName()).arg(get_ossl_verify_error(rc)));
			msg.setInformativeText(crt->getExtByNid(NID_name_constraints).getValue());
			msg.addButton(QMessageBox::Ok, tr("Edit extensions"));
			msg.addButton(QMessageBox::Close, tr("Abort rollout"));
			msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
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
	}
	XcaDetail::accept();
}

void NewX509::showTemp(QWidget *parent, pki_temp *x)
{
	if (!x)
		return;
	NewX509 *dlg = new NewX509(parent);
	dlg->setTemp(x);
	dlg->exec();
	delete dlg;
}
