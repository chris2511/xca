/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pki_temp.h"
#include "func.h"
#include "db.h"
#include "exception.h"
#include "widgets/MainWindow.h"
#include <QtCore/QDir>

QPixmap *pki_temp::icon=  NULL;

pki_temp::pki_temp(const pki_temp *pk)
	:pki_x509name(pk->desc)
{
	class_name = pk->class_name;
	dataVersion=pk->dataVersion;
	pkiType=pk->pkiType;

	xname=pk->xname;
	subAltName=pk->subAltName;
	issAltName=pk->issAltName;
	crlDist=pk->crlDist;
	authInfAcc=pk->authInfAcc;
	certPol=pk->certPol;
	nsCertType=pk->nsCertType;
	nsComment=pk->nsComment;
	nsBaseUrl=pk->nsBaseUrl;
	nsRevocationUrl=pk->nsRevocationUrl;
	nsCARevocationUrl=pk->nsCARevocationUrl;
	nsRenewalUrl=pk->nsRenewalUrl;
	nsCaPolicyUrl=pk->nsCaPolicyUrl;
	nsSslServerName=pk->nsSslServerName;
	ca=pk->ca;
	bcCrit=pk->bcCrit;
	keyUseCrit=pk->keyUseCrit;
	eKeyUseCrit=pk->eKeyUseCrit;
	subKey=pk->subKey;
	authKey=pk->authKey;
	pathLen=pk->pathLen;
	validN=pk->validN;
	validM=pk->validM;
	validMidn=pk->validMidn;
	keyUse=pk->keyUse;
	eKeyUse=pk->eKeyUse;
	adv_ext=pk->adv_ext;
	noWellDefined=pk->noWellDefined;
}

pki_temp::pki_temp(const QString d)
	:pki_x509name(d)
{
	class_name = "pki_temp";
	dataVersion=6;
	pkiType=tmpl;

	subAltName="";
	issAltName="";
	crlDist="";
	authInfAcc="";
	certPol="";
	nsCertType=0;
	nsComment="xca certificate";
	nsBaseUrl="";
	nsRevocationUrl="";
	nsCARevocationUrl="";
	nsRenewalUrl="";
	nsCaPolicyUrl="";
	nsSslServerName="";
	ca=0;
	bcCrit=false;
	keyUseCrit=false;
	eKeyUseCrit=false;
	subKey=false;
	authKey=false;
	validMidn=false;
	pathLen="";
	validN=365;
	validM=0;
	keyUse=0;
	eKeyUse="";
	adv_ext="";
	noWellDefined=false;
}

QString pki_temp::getMsg(msg_type msg)
{
	/*
	 * We do not construct english sentences from fragments
	 * to allow proper translations.
	 *
	 * %1 will be replaced by the internal name of the template
	 */
	switch (msg) {
	case msg_import: return tr("Successfully imported the XCA template '%1'");
	case msg_delete: return tr("Delete the XCA template '%1'?");
	case msg_create: return tr("Successfully created the XCA template '%1'");
	/* %1: Number of ktemplates; %2: list of templatenames */
	case msg_delete_multi: return tr("Delete the %1 XCA templates: %2?");
	}
	return pki_base::getMsg(msg);
}

x509name pki_temp::getSubject() const
{
	return xname;
}

static int bitsToInt(extList &el, int nid, bool *crit)
{
	int ret = 0, i = el.idxByNid(nid);

	if (i != -1) {
		if (crit)
			*crit = el[i].getCritical();
		ASN1_BIT_STRING *bits;
		bits = (ASN1_BIT_STRING *)el[i].d2i();

		for (int j=0; j<9; j++) {
			if (ASN1_BIT_STRING_get_bit(bits, j))
				ret |= 1 << j;
		}
		el.removeAt(i);
	}
	return ret;
}

extList pki_temp::fromCert(pki_x509super *cert_or_req)
{
	int i;
	x509name n;
	extList el = cert_or_req->getV3ext();

	nsComment = "";

	n = cert_or_req->getSubject();
	for (i=0; i<EXPLICIT_NAME_CNT; i++) {
		int nid = NewX509::name_nid[i];
		QString ne = n.popEntryByNid(nid);
		if (!ne.isNull())
			xname.addEntryByNid(nid, ne);
	}
	for (int i=0; i<n.entryCount(); i++) {
		int nid = n.nid(i);
		if (nid != NID_undef)
			xname.addEntryByNid(nid, n.getEntry(i));
	}

	el.genConf(NID_subject_alt_name, &subAltName, &adv_ext);
	el.genConf(NID_issuer_alt_name, &issAltName, &adv_ext);
	el.genConf(NID_crl_distribution_points, &crlDist, &adv_ext);
	el.genConf(NID_info_access, &authInfAcc, &adv_ext);

	el.genConf(NID_netscape_comment, &nsComment);
	el.genConf(NID_netscape_base_url, &nsBaseUrl);
	el.genConf(NID_netscape_revocation_url, &nsRevocationUrl);
	el.genConf(NID_netscape_ca_revocation_url, &nsCARevocationUrl);
	el.genConf(NID_netscape_renewal_url, &nsRenewalUrl);
	el.genConf(NID_netscape_ca_policy_url, &nsCaPolicyUrl);
	el.genConf(NID_netscape_ssl_server_name, &nsSslServerName);

	QString r;
	if (el.genConf(NID_basic_constraints, &r)) {
		QStringList sl = r.split(",");
		if (sl.contains("critical"))
			bcCrit = true;
		ca = sl.contains("CA:TRUE") ? 1 : 2;
		pathLen = sl.filter("pathlen:").join("").mid(8, -1);
	} else {
		bcCrit = false;
		ca = 0;
	}
	authKey = el.delByNid(NID_authority_key_identifier);
	subKey =  el.delByNid(NID_subject_key_identifier);

	nsCertType = bitsToInt(el, NID_netscape_cert_type, NULL);
	/* bit 4 is unused. Move higher bits down. */
	nsCertType = (nsCertType & 0xf) | ((nsCertType & 0xf0) >> 1);

	keyUse = bitsToInt(el, NID_key_usage, &keyUseCrit);

	el.genConf(NID_ext_key_usage, &eKeyUse);
	if (eKeyUse.startsWith("critical,")) {
		eKeyUseCrit = true;
		eKeyUse = eKeyUse.mid(9, -1);
	}
	el.genGenericConf(&adv_ext);

	if (cert_or_req->getType() == x509) {
		pki_x509 *cert = (pki_x509*)cert_or_req;
		if (cert->getNotAfter().isUndefined()) {
			noWellDefined = true;
		} else {
			a1time notBefore = cert->getNotBefore();
			a1time notAfter  = cert->getNotAfter();

			if (notBefore.toPlain().endsWith("000000Z") &&
			    notAfter.toPlain().endsWith("235959Z"))
			{
				validMidn = true;
			}

			int diff = notBefore.daysTo(notAfter);
			validM = 0;
			if (diff > 60) {
				validM = 1;
				diff /= 30;
				if (diff > 24) {
					validM = 2;
					diff /= 12;
				}
			}
			validN = diff;
		}
	}
	return el;
}

void pki_temp::fromData(const unsigned char *p, db_header_t *head )
{
	int version, size;

	size = head->len - sizeof(db_header_t);
	version = head->version;
	fromData(p, size, version);
}

static QString old_eKeyUse2QString(int old)
{
	QStringList sl;
	NIDlist eku_nid = *MainWindow::eku_nid;

        for (int i=0; i<eku_nid.count(); i++) {
		if (old & (1<<i)) {
			sl << OBJ_nid2sn(eku_nid[i]);
		}
	}
	return sl.join(", ");
}

void pki_temp::fromData(const unsigned char *p, int size, int version)
{
	QByteArray ba((const char*)p, size);

	destination = db::stringFromData(ba);
	bcCrit = db::boolFromData(ba);
	keyUseCrit = db::boolFromData(ba);
	eKeyUseCrit = db::boolFromData(ba);
	subKey = db::boolFromData(ba);
	authKey = db::boolFromData(ba);
	ca = db:: intFromData(ba);
	if (version > 5) {
		pathLen = db::stringFromData(ba);
	} else {
		pathLen = QString::number(db::intFromData(ba));
		if (pathLen == "0")
			pathLen = "";
	}
	validN = db::intFromData(ba);
	validM = db::intFromData(ba);
	keyUse = db::intFromData(ba);
	if (version > 4) {
		eKeyUse = db::stringFromData(ba);
	} else {
		int old = db::intFromData(ba);
		eKeyUse = old_eKeyUse2QString(old);
	}
	nsCertType = db::intFromData(ba);
	subAltName = db::stringFromData(ba);
	issAltName = db::stringFromData(ba);
	crlDist = db::stringFromData(ba);
	nsComment = db::stringFromData(ba);
	nsBaseUrl = db::stringFromData(ba);
	nsRevocationUrl = db::stringFromData(ba);
	nsCARevocationUrl = db::stringFromData(ba);
	nsRenewalUrl = db::stringFromData(ba);
	nsCaPolicyUrl = db::stringFromData(ba);
	nsSslServerName = db::stringFromData(ba);
	xname.d2i(ba);
	authInfAcc = db::stringFromData(ba);
	certPol = db::stringFromData(ba);
	validMidn = db::boolFromData(ba);
	if (version>2)
		adv_ext = db::stringFromData(ba);
	if (version>3)
		noWellDefined = db::boolFromData(ba);

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

QByteArray pki_temp::toData()
{
	QByteArray ba;

	ba += db::stringToData(destination);
	ba += db::boolToData(bcCrit);
	ba += db::boolToData(keyUseCrit);
	ba += db::boolToData(eKeyUseCrit);
	ba += db::boolToData(subKey);
	ba += db::boolToData(authKey);
	ba += db::intToData(ca);
	ba += db::stringToData(pathLen);
	ba += db::intToData(validN);
	ba += db::intToData(validM);
	ba += db::intToData(keyUse);
	ba += db::stringToData(eKeyUse);
	ba += db::intToData(nsCertType);
	ba += db::stringToData(subAltName);
	ba += db::stringToData(issAltName);
	ba += db::stringToData(crlDist);
	ba += db::stringToData(nsComment);
	ba += db::stringToData(nsBaseUrl);
	ba += db::stringToData(nsRevocationUrl);
	ba += db::stringToData(nsCARevocationUrl);
	ba += db::stringToData(nsRenewalUrl);
	ba += db::stringToData(nsCaPolicyUrl);
	ba += db::stringToData(nsSslServerName);
	ba += xname.i2d();
	ba += db::stringToData(authInfAcc);
	ba += db::stringToData(certPol);
	ba += db::boolToData(validMidn);
	ba += db::stringToData(adv_ext);
	ba += db::boolToData(noWellDefined);

	return ba;
}

void pki_temp::writeDefault(const QString fname)
{
	writeTemp(fname + QDir::separator() + getIntName() + ".xca");
}

void pki_temp::writeTemp(QString fname)
{
	QByteArray data, header;
	FILE *fp = fopen(QString2filename(fname),"w");

	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	data = toData();
	header = db::intToData(data.count());
	header += db::intToData(dataVersion);
	header += data;
	fwrite_ba(fp, header, fname);
	fclose(fp);
}

void pki_temp::fload(QString fname)
{
	int size, s, version;
	const int hsize = 2 * sizeof(uint32_t);
	char buf[hsize];
	unsigned char *p;
	FILE *fp = fopen(QString2filename(fname),"r");
	bool oldimport = false;

	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	if (fread(buf, hsize, 1, fp) != 1) {
		fclose(fp);
		my_error(tr("Template file content error (too small): %1").
			arg(fname));
	}

	QByteArray header(buf, hsize);
	QByteArray backup = header;

	size = db::intFromData(header);
	version = db::intFromData(header);

	if (size > 65535 || size <0) {
		/* oldimport templates are prepended by its size in host endianess.
		   Set fp after the first int and recover the size */
		fseek(fp, sizeof(int), SEEK_SET);
                size = intFromData(backup);
		if (size > 65535 || size <0) {
			fclose(fp);
			my_error(tr("Template file content error (bad size): %1 ").arg(fname));
		}
		oldimport = true;
	}
	p = (unsigned char *)OPENSSL_malloc(size);
	if (p) {
		if ((s=fread(p, 1, size, fp)) != size) {
			OPENSSL_free(p);
			fclose(fp);
			my_error(tr("Template file content error (bad length) :%1").arg(fname));
		}
	}
	if (oldimport)
		oldFromData(p, size);
	else
		fromData(p, size, version);
	OPENSSL_free(p);

	setIntName(rmslashdot(fname));
	fclose(fp);
}

pki_temp::~pki_temp()
{

}

bool pki_temp::compare(pki_base *)
{
	// we don't care if templates with identical contents
	// are stored in the database ...
	return false;
}

QVariant pki_temp::column_data(dbheader *hd)
{
	switch (hd->id) {
		case HD_temp_type:
			return QVariant(destination);
	}
	return pki_x509name::column_data(hd);
}

QVariant pki_temp::getIcon(dbheader *hd)
{
	return hd->id == HD_internal_name ? QVariant(*icon) : QVariant();
}

void pki_temp::oldFromData(unsigned char *p, int size)
{
	int version;

	QByteArray ba((const char*)p, size);

	version=intFromData(ba);
	intFromData(ba); /* type */
	if (version == 1) {
		ca = 2;
		bool mca = intFromData(ba);
		if (mca) ca = 1;
	}
	bcCrit=db::boolFromData(ba);
	keyUseCrit=db::boolFromData(ba);
	eKeyUseCrit=db::boolFromData(ba);
	subKey=db::boolFromData(ba);
	authKey=db::boolFromData(ba);
	db::boolFromData(ba);
	db::boolFromData(ba);
	if (version >= 2) {
		ca = intFromData(ba);
	}
	pathLen = QString::number(db::intFromData(ba));
	if (pathLen == "0")
		pathLen = "";
	validN = intFromData(ba);
	validM = intFromData(ba);
	keyUse=intFromData(ba);
	int old=db::intFromData(ba);
	eKeyUse = old_eKeyUse2QString(old);
	nsCertType=intFromData(ba);
	if (version == 1) {
		xname.addEntryByNid(OBJ_sn2nid("C"), db::stringFromData(ba));
		xname.addEntryByNid(OBJ_sn2nid("ST"), db::stringFromData(ba));
		xname.addEntryByNid(OBJ_sn2nid("L"), db::stringFromData(ba));
		xname.addEntryByNid(OBJ_sn2nid("O"), db::stringFromData(ba));
		xname.addEntryByNid(OBJ_sn2nid("OU"), db::stringFromData(ba));
		xname.addEntryByNid(OBJ_sn2nid("CN"), db::stringFromData(ba));
		xname.addEntryByNid(OBJ_sn2nid("Email"),db::stringFromData(ba));
	}
	subAltName=db::stringFromData(ba);
	issAltName=db::stringFromData(ba);
	crlDist=db::stringFromData(ba);
	nsComment=db::stringFromData(ba);
	nsBaseUrl=db::stringFromData(ba);
	nsRevocationUrl=db::stringFromData(ba);
	nsCARevocationUrl=db::stringFromData(ba);
	nsRenewalUrl=db::stringFromData(ba);
	nsCaPolicyUrl=db::stringFromData(ba);
	nsSslServerName=db::stringFromData(ba);
	// next version:
	if (version >= 2) {
		xname.d2i(ba);
	}
	if (version >= 3) {
		authInfAcc=db::stringFromData(ba);
		certPol=db::stringFromData(ba);
		validMidn=db::boolFromData(ba);
	}

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

