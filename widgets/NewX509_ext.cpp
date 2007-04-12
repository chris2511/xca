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
#include <qlineedit.h>
#include <qlistwidget.h>
#include "MainWindow.h"
#include "lib/x509v3ext.h"


x509v3ext NewX509::getBasicConstraints()
{
	QStringList cont;
	x509v3ext ext;
	QString ca[] = { "", "CA:TRUE", "CA:FALSE" };
	if (basicCA->currentIndex() > 0) {
		if (bcCritical->isChecked())
			cont << "critical";
		cont << ca[basicCA->currentIndex()];
		if (!basicPath->text().isEmpty())
			cont << (QString)"pathlen:" + basicPath->text();
		ext.create(NID_basic_constraints, cont.join(", "));
	}
	return ext;
}

void NewX509::setBasicConstraints(const x509v3ext &e)
{
	if (e.nid() != NID_basic_constraints) return;
	BASIC_CONSTRAINTS *bc;
	x509v3ext ex = e;
	bc = (BASIC_CONSTRAINTS *)ex.d2i();
	if (bc) {
		bcCritical->setChecked(bc->ca);
		a1int pl(bc->pathlen);
		basicPath->setText(QString::number(pl.getLong()));
	}
}

x509v3ext NewX509::getSubKeyIdent()
{
	x509v3ext ext;
	if (subKey->isChecked())
		ext.create(NID_subject_key_identifier, "hash", &ext_ctx);
	return ext;
}


x509v3ext NewX509::getAuthKeyIdent()
{
	x509v3ext ext;
	if (authKey->isChecked() && authKey->isEnabled()) {
		if (foreignSignRB->isChecked())
			ext.create(NID_authority_key_identifier,
				"keyid,issuer:always", &ext_ctx);
                else
			ext.create(NID_authority_key_identifier,
				"keyid:always", &ext_ctx);
	}
	return ext;
}

x509v3ext NewX509::getKeyUsage()
{
	QString keyusage[] = {
		"digitalSignature", "nonRepudiation", "keyEncipherment",
		"dataEncipherment", "keyAgreement", "keyCertSign",
		"cRLSign", "encipherOnly", "decipherOnly"
	};

	QStringList cont;
	x509v3ext ext;

	int rows = keyUsage->count();
	for (int i=0; i<rows; i++) {
		if (keyUsage->isItemSelected(keyUsage->item(i))) {
			cont << keyusage[i];
		}
	}
	if (kuCritical->isChecked() && cont.count() > 0)
		cont.prepend("critical");
	ext.create(NID_key_usage, cont.join(", "));
	return ext;
}

x509v3ext NewX509::getEkeyUsage()
{
	QStringList cont;
	x509v3ext ext;

	int rows = ekeyUsage->count();
	for (int i=0; i<rows; i++) {
		//QListWidgetItem *li = ekeyUsage->item(i);
		//printf("rows = %d, ekeyUsage = %d, %p\n", rows, i, li);
		if (ekeyUsage->isItemSelected(ekeyUsage->item(i))) {
			cont << (QString)OBJ_nid2sn(eku_nid[i]);
		}
	}
	if (ekuCritical->isChecked() && cont.count() > 0)
		cont.prepend("critical");
	ext.create(NID_ext_key_usage, cont.join(", "));
	return ext;
}

x509v3ext NewX509::getSubAltName()
{
	x509v3ext ext;
	QString s = subAltName->text();
	if (pt == x509_req) {
		QStringList sn, sl = s.split(',');
		foreach (QString str, sl) {
			if (str != "email:copy")
				sn += str;
		}
		s = sn.join(",");
	}
	ext.create(NID_subject_alt_name, s, &ext_ctx);
	return ext;
}

x509v3ext NewX509::getIssAltName()
{
	x509v3ext ext;
	QString s = issAltName->text();
	if (pt == x509_req) {
		QStringList sn, sl = s.split(',');
		foreach (QString str, sl) {
			if (str != "issuer:copy")
				sn += str;
		}
		s = sn.join(",");
	}
	ext.create(NID_issuer_alt_name, s, &ext_ctx);
	return ext;
}

x509v3ext NewX509::getCrlDist()
{
	x509v3ext ext;
	if (!crlDist->text().isEmpty()) {
		ext.create(NID_crl_distribution_points, crlDist->text());
	}
	return ext;
}

QString NewX509::getAuthInfAcc_string()
{
	QString rval="";
	QString aia_txt	= authInfAcc->text();
	aia_txt = aia_txt.trimmed();

	if (!aia_txt.isEmpty()) {
		rval = OBJ_nid2sn(aia_nid[aiaOid->currentIndex()]);
		rval += ";" + aia_txt;
	}
	return rval;
}

void NewX509::setAuthInfAcc_string(QString aia_txt)
{
	QStringList aia;
	int nid;

	aia = aia_txt.split(';');

	if (aia.count() != 2) return;

	nid = OBJ_sn2nid(CCHAR(aia[0]));

	for (int i=0; i < aia_nid.count(); i++) {
		if (aia_nid[i] == nid) {
			aiaOid->setCurrentIndex(i);
		}
	}
	authInfAcc->setText(aia[1]);
}

x509v3ext NewX509::getAuthInfAcc()
{
	x509v3ext ext;
	QString aia_txt = getAuthInfAcc_string();

	if (!aia_txt.isEmpty()) {
		ext.create(NID_info_access, aia_txt);
	}
	return ext;
}

x509v3ext NewX509::getCertPol()
{
	x509v3ext ext;
#if 0
	if (!certPol->text().isEmpty()) {
		ext.create(NID_certificate_policies, certPol->text(), &ext_ctx);
	}
#endif
	return ext;
}

extList NewX509::getAllExt()
{
	extList ne;

	ne << getBasicConstraints();
	ne << getSubKeyIdent();
	ne << getAuthKeyIdent();
	ne << getKeyUsage();
	ne << getEkeyUsage();
	ne << getSubAltName();
	ne << getIssAltName();
	ne << getCrlDist();
	ne += getNetscapeExt();
	return ne;

}

extList NewX509::getNetscapeExt()
{
	QString certTypeList[] = {
		"client", "server",  "email", "objsign",
		"sslCA",  "emailCA", "objCA" };


	QStringList cont;
	x509v3ext ext;
	extList el;

	int rows = nsCertType->count();
	for (int i=0; i<rows; i++) {
		if (nsCertType->isItemSelected(nsCertType->item(i))) {
			cont <<  certTypeList[i];
		}
	}

	el << ext.create(NID_netscape_cert_type, cont.join(", "));
	el << ext.create(NID_netscape_base_url, nsBaseUrl->text());
	el << ext.create(NID_netscape_revocation_url, nsRevocationUrl->text());
	el << ext.create(NID_netscape_ca_revocation_url, nsCARevocationUrl->text());
	el << ext.create(NID_netscape_renewal_url, nsRenewalUrl->text());
	el << ext.create(NID_netscape_ca_policy_url, nsCaPolicyUrl->text());
	el << ext.create(NID_netscape_ssl_server_name, nsSslServerName->text());
	el << ext.create(NID_netscape_comment, nsComment->text());
	return el;
}

void NewX509::initCtx(pki_x509 *subj, pki_x509 *iss, pki_x509req *req)
{
	X509 *s = NULL, *s1 = NULL;
	X509_REQ *r = NULL;

	if (subj) s1 = subj->getCert();
	if (iss) s = iss->getCert();
	if (req) r = req->getReq();

	memset(&ext_ctx, 0, sizeof(X509V3_CTX));
	X509V3_set_ctx(&ext_ctx, s, s1, r, NULL, 0);
}

void NewX509::setExt(const x509v3ext &ext)
{
	switch (ext.nid()) {
		case NID_basic_constraints:
			bcCritical->setChecked(ext.getCritical());
	}
}

QString NewX509::createRequestText()
{
	return "---";
	extList ne;

	ne << getBasicConstraints();
	ne << getSubKeyIdent();
	ne << getAuthKeyIdent();
	ne << getKeyUsage();
	ne << getEkeyUsage();
	ne << getSubAltName();
	ne << getIssAltName();
	ne << getCrlDist();

	return ne.getHtml("<br>") + getNetscapeExt().getHtml("<br>");
}
