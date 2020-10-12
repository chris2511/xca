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
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>

#include "MainWindow.h"
#include "lib/x509v3ext.h"
#include "lib/BioByteArray.h"
#include "lib/func.h"

#include "lib/openssl_compat.h"

x509v3ext NewX509::getBasicConstraints()
{
	QStringList cont;
	x509v3ext ext;
	QString ca[] = { "", "CA:TRUE", "CA:FALSE" };
	if (basicCA->currentIndex() > 0) {
		if (bcCritical->isChecked())
			cont << "critical";
		cont << ca[basicCA->currentIndex()];
		if (basicCA->currentIndex() == 1 &&
		   !basicPath->text().isEmpty())
		{
			cont << QString("pathlen:") +
				QString::number(basicPath->text().toInt());
		}
		ext.create(NID_basic_constraints, cont.join(", "), &ext_ctx);
	}
	return ext;
}

x509v3ext NewX509::getSubKeyIdent()
{
	x509v3ext ext;
	if (subKey->isChecked())
		ext.create(NID_subject_key_identifier, "hash", &ext_ctx);
	return ext;
}


x509v3ext NewX509::getOCSPstaple()
{
	x509v3ext ext;
	if (OCSPstaple->isChecked())
		ext.create(NID_tlsfeature,
#ifdef NID_tlsfeature
			"status_request",
#else
			"DER:30:03:02:01:05",
#endif
			&ext_ctx);
	return ext;
}

x509v3ext NewX509::getAuthKeyIdent()
{
	x509v3ext ext;
	if (!authKey->isChecked() || !authKey->isEnabled())
		return ext;

	QString x = "keyid,issuer";
	ext.create(NID_authority_key_identifier, x, &ext_ctx);
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
		if (keyUsage->item(i)->isSelected())
			cont << keyusage[i];
	}
	if (kuCritical->isChecked() && cont.count() > 0)
		cont.prepend("critical");
	ext.create(NID_key_usage, cont.join(", "), &ext_ctx);
	return ext;
}

x509v3ext NewX509::getEkeyUsage()
{
	QStringList cont;
	x509v3ext ext;

	int rows = ekeyUsage->count();
	for (int i=0; i<rows; i++) {
		if (ekeyUsage->item(i)->isSelected())
			cont << QString(OBJ_nid2sn(extkeyuse_nid[i]));
	}
	if (ekuCritical->isChecked() && cont.count() > 0)
		cont.prepend("critical");
	ext.create(NID_ext_key_usage, cont.join(", "), &ext_ctx);
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
		ext.create(NID_crl_distribution_points, crlDist->text(), &ext_ctx);
	}
	return ext;
}

x509v3ext NewX509::getAuthInfAcc()
{
	x509v3ext ext;
	if (!authInfAcc->text().isEmpty()) {
		ext.create(NID_info_access, authInfAcc->text(), &ext_ctx);
	}
	return ext;
}

extList NewX509::getAdvanced()
{
	QString conf_str;
	CONF *conf;
	extList elist;
	long err_line=0;
	STACK_OF(X509_EXTENSION) **sk, *sk_tmp = NULL;
	const STACK_OF(X509_EXTENSION) *csk;
	const char *ext_name = "default";
	int ret, start;

	if (nconf_data->isReadOnly()) {
		conf_str = v3ext_backup;
	} else {
		conf_str = nconf_data->toPlainText();
	}
	if (conf_str.isEmpty())
		return elist;

	conf = NCONF_new(NULL);
	ret = NCONF_load_bio(conf, BioByteArray(conf_str.toLatin1()).ro(),
				&err_line);
	if (ret != 1) {
		openssl_error(tr("Configfile error on line %1\n").
				arg(err_line));
		return elist;
	}

	if (ext_ctx.subject_cert) {
		csk = X509_get0_extensions(ext_ctx.subject_cert);
		start = csk? sk_X509_EXTENSION_num(csk): 0;
	} else {
		sk = &sk_tmp;
		start = 0;
	}

	X509V3_set_nconf(&ext_ctx, conf);

	if (ext_ctx.subject_cert) {
		if (X509V3_EXT_add_nconf(conf, &ext_ctx,
				(char *) ext_name, ext_ctx.subject_cert))
			openssl_error();
		csk = X509_get0_extensions(ext_ctx.subject_cert);
	} else {
		if (X509V3_EXT_add_nconf_sk(conf, &ext_ctx, (char *)ext_name, sk))
			openssl_error();
		csk = *sk;
	}

	elist.setStack(csk, start);
	if (!ext_ctx.subject_cert)
		sk_X509_EXTENSION_pop_free(sk_tmp, X509_EXTENSION_free);

	X509V3_set_nconf(&ext_ctx, NULL);
	NCONF_free(conf);
	openssl_error();
	return elist;
}

extList NewX509::getGuiExt()
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
	ne << getAuthInfAcc();
	ne << getOCSPstaple();
	openssl_error();
	return ne;
}

extList NewX509::getAllExt()
{
	extList ne;
	ne = getGuiExt();
	ne += getAdvanced();
	if (!Settings["disable_netscape"])
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
		if (nsCertType->item(i)->isSelected())
			cont << certTypeList[i];
	}

	el << ext.create(NID_netscape_cert_type, cont.join(", "), &ext_ctx);
	el << ext.create_ia5(NID_netscape_base_url, nsBaseUrl->text(), &ext_ctx);
	el << ext.create_ia5(NID_netscape_revocation_url, nsRevocationUrl->text(), &ext_ctx);
	el << ext.create_ia5(NID_netscape_ca_revocation_url, nsCARevocationUrl->text(), &ext_ctx);
	el << ext.create_ia5(NID_netscape_renewal_url, nsRenewalUrl->text(), &ext_ctx);
	el << ext.create_ia5(NID_netscape_ca_policy_url, nsCaPolicyUrl->text(), &ext_ctx);
	el << ext.create_ia5(NID_netscape_ssl_server_name, nsSslServerName->text(), &ext_ctx);
	el << ext.create_ia5(NID_netscape_comment, nsComment->text(), &ext_ctx);
	return el;
}

void NewX509::initCtx(pki_x509 *subj, pki_x509 *iss, pki_x509req *req)
{
	X509 *s = NULL, *s1 = NULL;
	X509_REQ *r = NULL;

	if (subj) s1 = subj->getCert();
	if (iss) s = iss->getCert();
	if (req) r = req->getReq();

	X509V3_set_ctx(&ext_ctx, s, s1, r, NULL, 0);
}

extList NewX509::getExtDuplicates()
{
	int i, start, cnt, n1, n;
	x509v3ext e;
	const STACK_OF(X509_EXTENSION) *sk;
	extList el_dup, el;
	QString olist;

	if (ext_ctx.subject_cert) {
		sk = X509_get0_extensions(ext_ctx.subject_cert);
	} else
		return el_dup;

	el.setStack(sk, 0);
	cnt = el.size();
	for (start=0; start < cnt; start++) {
		n1 = el[start].nid();
		for (i = start+1; i<cnt; i++) {
			e = el[i];
			n = e.nid();
			if (n1 == n) {
				// DUPLICATE
				if (el_dup.idxByNid(n1) ==-1)
					el_dup << e;

			}
		}
        }
	return el_dup;
}
