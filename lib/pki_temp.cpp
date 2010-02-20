/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_temp.h"
#include "func.h"
#include "db.h"
#include "exception.h"
#include <qdir.h>
#include "widgets/MainWindow.h"

QPixmap *pki_temp::icon=  NULL;

pki_temp::pki_temp(const pki_temp *pk)
	:pki_base(pk->desc)
{
	class_name = pk->class_name;
	dataVersion=pk->dataVersion;
	pkiType=pk->pkiType;
	cols=pk->cols;

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
	:pki_base(d)
{
	class_name = "pki_temp";
	dataVersion=6;
	pkiType=tmpl;
	cols=2;

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

static QStringList extVlistToString(extList &el, int nid, bool *crit)
{
	int i = el.idxByNid(nid);
	QStringList sl;
	if (i != -1) {
		if (crit)
			*crit = el[i].getCritical();
		sl = el[i].i2v();
		el.removeAt(i);
	}
	return sl;
}

static QString extVtoString(extList &el, int nid, bool *crit)
{
	return extVlistToString(el, nid, crit).join(", ");
}

static QString extToString(extList &el, int nid)
{
	int i = el.idxByNid(nid);
	if (i != -1) {
		QString s = el[i].i2s();
		el.removeAt(i);
		return s;
	}
	return QString();
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

	subAltName = extVtoString(el, NID_subject_alt_name, NULL);
	issAltName = extVtoString(el, NID_issuer_alt_name, NULL);
	crlDist = extVtoString(el, NID_crl_distribution_points, NULL);

	authInfAcc = extVtoString(el, NID_info_access, NULL);
	if (!authInfAcc.isEmpty()) {
		authInfAcc.replace(QRegExp(" - "), ";");
		authInfAcc.replace(QRegExp(";IP Address"), ";IP");
		authInfAcc.replace(QRegExp(";Registered ID"), ";RID");
	}

	nsComment = extToString(el, NID_netscape_comment);
	nsBaseUrl = extToString(el, NID_netscape_base_url);
	nsRevocationUrl = extToString(el, NID_netscape_revocation_url);
	nsCARevocationUrl = extToString(el, NID_netscape_ca_revocation_url);
	nsRenewalUrl = extToString(el, NID_netscape_renewal_url);
	nsCaPolicyUrl = extToString(el, NID_netscape_ca_policy_url);
	nsSslServerName = extToString(el, NID_netscape_ssl_server_name);

	i = el.idxByNid(NID_basic_constraints);
	if (i != -1) {
		BASIC_CONSTRAINTS *bc;
		bc = (BASIC_CONSTRAINTS *)el[i].d2i();
	        if (bc) {
			bcCrit = el[i].getCritical();
			ca = (bc->ca ? 0 : 1) +1;
			a1int pl(bc->pathlen);
			pathLen = pl.toDec();
			BASIC_CONSTRAINTS_free(bc);
		}
		el.removeAt(i);
        }
	i = el.idxByNid(NID_authority_key_identifier);
	if (i != -1) {
		el.removeAt(i);
		authKey = true;
	}
	i = el.idxByNid(NID_subject_key_identifier);
	if (i != -1) {
		el.removeAt(i);
		subKey = true;
	}
	nsCertType = bitsToInt(el, NID_netscape_cert_type, NULL);
	/* bit 4 is unused. Move higher bits down. */
	nsCertType = (nsCertType & 0xf) | ((nsCertType & 0xf0) >> 1);

	keyUse = bitsToInt(el, NID_key_usage, &keyUseCrit);

	QStringList sl = extVlistToString(el, NID_ext_key_usage, &eKeyUseCrit);
	for (i=0; i<sl.size(); i++)
		sl[i] = OBJ_ln2sn(CCHAR(sl[i]));
	eKeyUse = sl.join(", ");

	if (cert_or_req->getType() == x509) {
		pki_x509 *cert = (pki_x509*)cert_or_req;
		if (cert->getNotAfter().isUndefined()) {
			noWellDefined = true;
		} else {
			struct tm nb, na;

			a1time notBefore = cert->getNotBefore();
			a1time notAfter  = cert->getNotAfter();

			if (notBefore.toPlain().endsWith("000000Z") &&
			    notAfter.toPlain().endsWith("235959Z"))
			{
				validMidn = true;
			}
			if (!notBefore.ymdg(&nb) &&
			    !notAfter.ymdg(&na))
			{
				time_t diff = mktime(&na) - mktime(&nb);
				diff /= SECONDS_PER_DAY;
				validM = 0;
				if (diff >60) {
					validM = 1;
					diff /= 30;
					if (diff >24) {
						validM = 2;
						diff /= 12;
					}
				}
				validN = diff;
			}
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
	const unsigned char *p1 = p;

	destination = db::stringFromData(&p1);
	bcCrit=db::boolFromData(&p1);
	keyUseCrit=db::boolFromData(&p1);
	eKeyUseCrit=db::boolFromData(&p1);
	subKey=db::boolFromData(&p1);
	authKey=db::boolFromData(&p1);
	ca =db:: intFromData(&p1);
	if (version > 5) {
		pathLen=db::stringFromData(&p1);
	} else {
		pathLen=QString::number(db::intFromData(&p1));
		if (pathLen == "0")
			pathLen = "";
	}
	validN =db::intFromData(&p1);
	validM =db::intFromData(&p1);
	keyUse=db::intFromData(&p1);
	if (version > 4) {
		eKeyUse=db::stringFromData(&p1);
	} else {
		int old=db::intFromData(&p1);
		eKeyUse = old_eKeyUse2QString(old);
	}
	nsCertType=db::intFromData(&p1);
	subAltName=db::stringFromData(&p1);
	issAltName=db::stringFromData(&p1);
	crlDist=db::stringFromData(&p1);
	nsComment=db::stringFromData(&p1);
	nsBaseUrl=db::stringFromData(&p1);
	nsRevocationUrl=db::stringFromData(&p1);
	nsCARevocationUrl=db::stringFromData(&p1);
	nsRenewalUrl=db::stringFromData(&p1);
	nsCaPolicyUrl=db::stringFromData(&p1);
	nsSslServerName=db::stringFromData(&p1);
	p1 = xname.d2i(p1, size - (p1-p));
	authInfAcc=db::stringFromData(&p1);
	certPol=db::stringFromData(&p1);
	validMidn=db::boolFromData(&p1);
	if (version>2)
		adv_ext=db::stringFromData(&p1);
	if (version>3)
		noWellDefined=db::boolFromData(&p1);
	if (p1-p != size) {
		my_error(tr("Wrong Size of template: ") + getIntName());
	}
}


unsigned char *pki_temp::toData(int *size)
{
	unsigned char *p, *p1;
	*size = dataSize();
	p = (unsigned char*)OPENSSL_malloc(*size);
	check_oom(p);
	p1 = p;

	db::stringToData(&p1, destination);
	db::boolToData(&p1, bcCrit);
	db::boolToData(&p1, keyUseCrit);
	db::boolToData(&p1, eKeyUseCrit);
	db::boolToData(&p1, subKey);
	db::boolToData(&p1, authKey);
	db::intToData(&p1, ca);
	db::stringToData(&p1, pathLen);
	db::intToData(&p1, validN);
	db::intToData(&p1, validM);
	db::intToData(&p1, keyUse);
	db::stringToData(&p1, eKeyUse);
	db::intToData(&p1, nsCertType);
	db::stringToData(&p1, subAltName);
	db::stringToData(&p1, issAltName);
	db::stringToData(&p1, crlDist);
	db::stringToData(&p1, nsComment);
	db::stringToData(&p1, nsBaseUrl);
	db::stringToData(&p1, nsRevocationUrl);
	db::stringToData(&p1, nsCARevocationUrl);
	db::stringToData(&p1, nsRenewalUrl);
	db::stringToData(&p1, nsCaPolicyUrl);
	db::stringToData(&p1, nsSslServerName);
	p1 = xname.i2d(p1);
	db::stringToData(&p1, authInfAcc);
	db::stringToData(&p1, certPol);
	db::boolToData(&p1, validMidn);
	db::stringToData(&p1, adv_ext);
	db::boolToData(&p1, noWellDefined);
	*size = p1-p;
	return p;
}

void pki_temp::writeDefault(const QString fname)
{
	writeTemp(fname + QDir::separator() + getIntName() + ".xca");
}

void pki_temp::writeTemp(QString fname)
{
	int size = 0;
	unsigned char *p, buf[2*sizeof(uint32_t)], *p1=buf;
	FILE *fp = fopen(QString2filename(fname),"w");

	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	p = toData(&size);
	db::intToData(&p1, size);
	db::intToData(&p1, dataVersion);
	fwrite(buf, 2*sizeof(uint32_t), 1, fp);
	fwrite(p, 1, size, fp);
	OPENSSL_free(p);
	fclose(fp);
}

void pki_temp::fload(QString fname)
{
	int size, s, version;
	bool oldimport;
	unsigned char *p, buf[2*sizeof(int)];
	const unsigned char *p1 = buf;
	FILE *fp = fopen(QString2filename(fname),"r");
	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	if (fread(buf, 2*sizeof(int), 1, fp) != 1)
		my_error(tr("Template file content error (too small): %1").
			arg(fname));
	size = db::intFromData(&p1);
	version = db::intFromData(&p1);

	if (size > 65535 || size <0) {
		fseek(fp, sizeof(int), SEEK_SET);
		p1 = buf;
		size = intFromData(&p1);
		if (size > 65535 || size <0) {
			fclose(fp);
			my_error(tr("Template file content error (bad size): %1").arg(fname));
		}
		oldimport = true;
	} else {
		oldimport = false;
	}
	p = (unsigned char *)OPENSSL_malloc(size);
	if (p) {
		if ((s=fread(p, 1, size, fp)) != size) {
			OPENSSL_free(p);
			fclose(fp);
			my_error(tr("Template file content error (bad length) :%1").arg(fname));
		}
	}
	if (oldimport) {
		oldFromData(p, size);
	} else {
		fromData(p, size, version);
	}
	OPENSSL_free(p);

	setIntName(rmslashdot(fname));
	fclose(fp);
}

pki_temp::~pki_temp()
{

}

int pki_temp::dataSize()
{
	int s = 5 * sizeof(uint32_t) + 7 * sizeof(char) +
	xname.derSize() + (
	subAltName.length() +
	issAltName.length() +
	crlDist.length() +
	authInfAcc.length() +
	certPol.length() +
	nsComment.length() +
	nsBaseUrl.length() +
	nsRevocationUrl.length() +
	nsCARevocationUrl.length() +
	nsRenewalUrl.length() +
	nsCaPolicyUrl.length() +
	nsSslServerName.length() +
	adv_ext.length() +
	eKeyUse.length() +
	pathLen.length() +
	16 ) * sizeof(char);
	return s;
}

bool pki_temp::compare(pki_base *)
{
	// we don't care if templates with identical contents
	// are stored in the database ...
	return false;
}

QVariant pki_temp::column_data(int col)
{
	switch (col) {
		case 0:
			return QVariant(getIntName());
		case 1:
			return QVariant(destination);
	}
	return QVariant();
}

QVariant pki_temp::getIcon(int column)
{
	return column == 0 ? QVariant(*icon) : QVariant();
}

void pki_temp::oldFromData(unsigned char *p, int size )
{
	const unsigned char *p1 = p;
	int type, version;
	bool dummy;

	version=intFromData(&p1);
	type=intFromData(&p1);
	if (version == 1) {
		ca = 2;
		bool mca = intFromData(&p1);
		if (mca) ca = 1;
	}
	bcCrit=db::boolFromData(&p1);
	keyUseCrit=db::boolFromData(&p1);
	eKeyUseCrit=db::boolFromData(&p1);
	subKey=db::boolFromData(&p1);
	authKey=db::boolFromData(&p1);
	dummy = db::boolFromData(&p1);
	dummy = db::boolFromData(&p1);
	if (version >= 2) {
		ca = intFromData(&p1);
	}
	pathLen = QString::number(db::intFromData(&p1));
	if (pathLen == "0")
		pathLen = "";
	validN = intFromData(&p1);
	validM = intFromData(&p1);
	keyUse=intFromData(&p1);
	int old=db::intFromData(&p1);
	eKeyUse = old_eKeyUse2QString(old);
	nsCertType=intFromData(&p1);
	if (version == 1) {
		xname.addEntryByNid(OBJ_sn2nid("C"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("ST"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("L"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("O"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("OU"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("CN"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("Email"),db::stringFromData(&p1));
	}
	subAltName=db::stringFromData(&p1);
	issAltName=db::stringFromData(&p1);
	crlDist=db::stringFromData(&p1);
	nsComment=db::stringFromData(&p1);
	nsBaseUrl=db::stringFromData(&p1);
	nsRevocationUrl=db::stringFromData(&p1);
	nsCARevocationUrl=db::stringFromData(&p1);
	nsRenewalUrl=db::stringFromData(&p1);
	nsCaPolicyUrl=db::stringFromData(&p1);
	nsSslServerName=db::stringFromData(&p1);
	// next version:
	if (version >= 2) {
		p1 = xname.d2i(p1, size - (p1-p));
	}
	if (version >= 3) {
		authInfAcc=db::stringFromData(&p1);
		certPol=db::stringFromData(&p1);
		validMidn=db::boolFromData(&p1);
	}

	if (p1-p != size) {
		openssl_error("Wrong Size");
	}
}

