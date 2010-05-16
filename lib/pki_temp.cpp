/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
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

static QString extVtoString(extList &el, int nid, QString *adv)
{
	bool crit;
	QString critical;
	const char *tag = OBJ_nid2sn(nid);

	QStringList vlist = extVlistToString(el, nid, &crit);
	if (crit)
		critical = "critical,";
	if (!vlist.join("").contains(","))
		return critical + vlist.join(", ");

	*adv = QString("%1=%2@%1_sect\n").arg(tag).arg(critical) + *adv +
		QString("\n[%1_sect]\n").arg(tag);

	for (int i=0; i<vlist.count(); i++) {
		QString s = vlist[i];
		int eq = s.indexOf(":");
		*adv += QString("%1.%2=%3\n").arg(s.left(eq)).
			arg(i).arg(s.mid(eq+1));
	}
	return QString();
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

	subAltName = extVtoString(el, NID_subject_alt_name, &adv_ext);
	issAltName = extVtoString(el, NID_issuer_alt_name, &adv_ext);
	crlDist = extVtoString(el, NID_crl_distribution_points, &adv_ext);

	authInfAcc = extVtoString(el, NID_info_access, &adv_ext);

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
	fwrite(header.constData(), 1, header.count(), fp);
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

void pki_temp::oldFromData(unsigned char *p, int size)
{
	int type, version;
	bool dummy;

	QByteArray ba((const char*)p, size);

	version=intFromData(ba);
	type=intFromData(ba);
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
	dummy = db::boolFromData(ba);
	dummy = db::boolFromData(ba);
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

