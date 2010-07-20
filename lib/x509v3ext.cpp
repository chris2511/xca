/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509v3ext.h"
#include "x509name.h"
#include "asn1int.h"
#include "func.h"
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <QtCore/QStringList>
#include "base.h"

x509v3ext::x509v3ext()
{
	ext = X509_EXTENSION_new();
}

x509v3ext::x509v3ext(const X509_EXTENSION *n)
{
	ext = X509_EXTENSION_dup((X509_EXTENSION *)n);
}

x509v3ext::x509v3ext(const x509v3ext &n)
{
	ext = NULL;
	set(n.ext);
}

x509v3ext::~x509v3ext()
{
	X509_EXTENSION_free(ext);
}

x509v3ext &x509v3ext::set(const X509_EXTENSION *n)
{
	if (ext != NULL)
		X509_EXTENSION_free(ext);
	ext = X509_EXTENSION_dup((X509_EXTENSION *)n);
	return *this;
}

x509v3ext &x509v3ext::create(int nid, const QString &et, X509V3_CTX *ctx)
{
	if (ext) {
		X509_EXTENSION_free(ext);
		ext = NULL;
	}
	if (!et.isEmpty()) {
		ext = X509V3_EXT_conf_nid(NULL, ctx, nid, (char*)CCHAR(et));
	}
	if (!ext)
		ext = X509_EXTENSION_new();
	else {
		if (ctx && ctx->subject_cert) {
			STACK_OF(X509_EXTENSION) **sk;
			sk = &ctx->subject_cert->cert_info->extensions;
			X509v3_add_ext(sk, ext, -1);
		}
	}
	return *this;
}

int x509v3ext::nid() const
{
	ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
	return OBJ_obj2nid(obj);
}

void *x509v3ext::d2i()
{
	return X509V3_EXT_d2i(ext);
}

x509v3ext &x509v3ext::operator = (const x509v3ext &x)
{
	set(x.ext);
	return *this;
}

QString x509v3ext::getObject() const
{
	QString a = OBJ_nid2ln(nid());
	return a;
}

int x509v3ext::getCritical() const
{
	return X509_EXTENSION_get_critical(ext);
}

QString x509v3ext::getValue(bool html) const
{
	QString text = "";
	int ret;
	char *p = NULL;
	BIO *bio = BIO_new(BIO_s_mem());

	ret = X509V3_EXT_print(bio, ext, X509V3_EXT_DEFAULT, 0);
	if (ret) {
		long len = BIO_get_mem_data(bio, &p);
		text = QString::fromLocal8Bit(p, len);
	}
	BIO_free(bio);
	if (html) {
		text.replace(QRegExp("&"), "&amp;");
		text.replace(QRegExp("<"), "&lt;");
		text.replace(QRegExp(">"), "&gt;");
		text.replace(QRegExp("\n"), "<br>\n");
	}
	return text.trimmed();
}

static QString vlist2Section(QStringList vlist, QString tag, QString *sect)
{
	/* Check for commas in the text */
	if (!vlist.join("").contains(","))
		return vlist.join(", ");

	*sect += QString("\n[%1_sect]\n").arg(tag);

	for (int i=0; i<vlist.count(); i++) {
		QString s = vlist[i];
		int eq = s.indexOf(":");
		*sect += QString("%1.%2=%3\n").arg(s.left(eq)).
			arg(i).arg(s.mid(eq+1));
	}
	return QString("@%1_sect\n").arg(tag);
}

static void *ext_str_new(X509_EXTENSION *ext)
{
	const X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
	const unsigned char *p = ext->value->data;
	void *ext_str;

	if(method->it)
		ext_str = ASN1_item_d2i(NULL, &p, ext->value->length, ASN1_ITEM_ptr(method->it));
        else
		ext_str = method->d2i(NULL, &p, ext->value->length);
	return ext_str;
}

static void ext_str_free(X509_EXTENSION *ext, void *ext_str)
{
	const X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);

	if (method->it)
		ASN1_item_free((ASN1_VALUE*)ext_str,ASN1_ITEM_ptr(method->it));
	else
		method->ext_free(ext_str);
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define C_X509V3_EXT_METHOD const X509V3_EXT_METHOD
#else
#define C_X509V3_EXT_METHOD X509V3_EXT_METHOD
#endif

bool x509v3ext::parse_i2s(QString *single, QString *adv) const
{
	C_X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
	void *ext_str;
	QString ret;

	if (!method->i2s)
		return false;
	ext_str = ext_str_new(ext);
	if (!ext_str)
		return false;
	ret = QString(method->i2s(method, ext_str));
	if (single)
		*single = ret;
	else
		*adv = QString("%1=%2").arg(OBJ_nid2sn(nid())).arg(ret);

	ext_str_free(ext, ext_str);
	return true;
}

static bool genName2conf(GENERAL_NAME *gen, QString tag, QString *single, QString *sect)
{
	unsigned char *p;
	QString ret;

	switch (gen->type) {
		case GEN_EMAIL: ret = "email:%1"; break;
		case GEN_DNS:   ret = "DNS:%1"; break;
		case GEN_URI:   ret = "URI:%1"; break;

		case GEN_DIRNAME: {
			tag += "_dirname";
			x509name xn(gen->d.dirn);
			*sect += QString("\n[%1]\n"). arg(tag);
			*sect += xn.taggedValues();
			*single = QString("dirName:") + tag;
			printf("GENN: '%s'\n'%s'\n", CCHAR(*single), CCHAR(*sect));
			return true;
		}
		case GEN_IPADD:
			p = gen->d.ip->data;
			if (gen->d.ip->length == 4) {
				*single = QString("IP:%1.%2.%3.%4").
						arg(p[0]).arg(p[1]).arg(p[2]).arg(p[3]);
				return true;
			}
			return false;

		case GEN_RID:
			*single = QString("RID:%1").arg(OBJ_obj2QString(gen->d.rid));
			return true;
		case GEN_OTHERNAME:
			if (gen->d.otherName->value->type != V_ASN1_UTF8STRING)
				return false;
			*single = QString("othername:%1;UTF8:%2").
				arg(OBJ_obj2QString(gen->d.otherName->type_id)).
				arg(asn1ToQString(
					gen->d.otherName->value->value.asn1_string, true));
			return true;
		default:
			return false;
	}
	if (!ret.isEmpty())
		*single = ret.arg(asn1ToQString(gen->d.ia5, true));
	return true;
}

static bool genNameStack2conf(STACK_OF(GENERAL_NAME) *gens, QString tag,
				QString *single, QString *sect)
{
	int i;
	QStringList sl;
	for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
		QString one;
		if (!genName2conf(sk_GENERAL_NAME_value(gens, i),
			QString("%1_%2").arg(tag).arg(i), &one, sect))
		{
			return false;
		}
		sl << one;
	}
	*single = vlist2Section(sl, tag, sect);
	return true;
}

QString x509v3ext::parse_critical() const
{
	return QString(getCritical() ? "critical," : "");
}

bool x509v3ext::parse_generalName(QString *single, QString *adv) const
{
	bool retval = true;
	QString sect, ret;
	QString tag = OBJ_nid2sn(nid());
	STACK_OF(GENERAL_NAME) *gens = (STACK_OF(GENERAL_NAME) *)ext_str_new(ext);

	if (!genNameStack2conf(gens, tag, &ret, &sect))
		retval = false;
	else if (sect.isEmpty() && single) {
		*single = parse_critical() + ret;
	} else {
		*adv = tag + "=" + parse_critical() + ret + *adv + sect;
	}
	ext_str_free(ext, gens);
	return retval;
}

bool x509v3ext::parse_eku(QString *single, QString *adv) const
{
	EXTENDED_KEY_USAGE *eku = ( EXTENDED_KEY_USAGE *)ext_str_new(ext);
	QStringList sl;
	int i;

	for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
		sl << QString(OBJ_obj2sn(sk_ASN1_OBJECT_value(eku, i)));
	}
	QString r = parse_critical() + sl.join(", ");
	if (single)
		*single = r;
	else
		*adv = QString("%1=%2").arg(OBJ_nid2sn(nid())).arg(r);
	return true;
}

bool x509v3ext::parse_ainfo(QString *single, QString *adv) const
{
	bool retval = true;
	QString sect, ret;
        QString tag = OBJ_nid2sn(nid());
	QStringList sl;
	int i;

	AUTHORITY_INFO_ACCESS *ainfo = (AUTHORITY_INFO_ACCESS *)ext_str_new(ext);

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ainfo); i++) {
		QString one;
		ACCESS_DESCRIPTION *desc = sk_ACCESS_DESCRIPTION_value(ainfo, i);
		if (!genName2conf(desc->location,
			QString("%1_%2").arg(tag).arg(i), &one, &sect))
		{
			retval = false;
			break;
		}
		sl << QString("%1;%2").arg(OBJ_obj2sn(desc->method)).arg(one);
	}
	if (retval) {
		ret = vlist2Section(sl, tag, &sect);
		if (sect.isEmpty() && sk_ACCESS_DESCRIPTION_num(ainfo) == 1) {
			*single = parse_critical() + ret;
		} else {
			*adv = tag + "=" + parse_critical() + ret + *adv + sect;
		}
	}
	ext_str_free(ext, ainfo);
	return retval;
}

static const BIT_STRING_BITNAME reason_flags[] = {
{0, "", "unused"},
{1, "", "keyCompromise"},
{2, "", "CACompromise"},
{3, "", "affiliationChanged"},
{4, "", "superseded"},
{5, "", "cessationOfOperation"},
{6, "", "certificateHold"},
{7, "", "privilegeWithdrawn"},
{8, "", "AACompromise"},
{-1, NULL, NULL}
};

bool x509v3ext::parse_Crldp(QString *single, QString *adv) const
{
	QString othersect;
	QStringList crldps;
	int i;

	STACK_OF(DIST_POINT) *crld = (STACK_OF(DIST_POINT)*)ext_str_new(ext);
	if (sk_DIST_POINT_num(crld) == 1) {
		DIST_POINT *point = sk_DIST_POINT_value(crld, 0);
		if (point->distpoint && !point->reasons && !point->CRLissuer &&
		    !point->distpoint->type && single)
		{
			QString sect, ret;
			if (!genNameStack2conf(point->distpoint->name.fullname,
						"", &ret, &sect))
				goto could_not_parse;

			if (sect.isEmpty()) {
				*single = parse_critical() +ret;
				return true;
			}
		}
	}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	for(i = 0; i < sk_DIST_POINT_num(crld); i++) {
		DIST_POINT *point = sk_DIST_POINT_value(crld, i);
		QString tag = QString("crlDistributionPoint%1_sect").arg(i);
		QString crldpsect = QString("\n[%1]\n").arg(tag);
		if (point->distpoint) {
			if (!point->distpoint->type) {
				QString ret;
				if (!genNameStack2conf(point->distpoint->name.fullname,
						tag + "_fullname", &ret, &othersect))
					goto could_not_parse;

				crldpsect += "fullname=" + ret +"\n";
			} else {
				QString mysect = tag + "_relativename";
				x509name xn(point->distpoint->name.relativename);
				crldpsect += "relativename=" + mysect + "\n";
				othersect += QString("\n[%1]\n").arg(mysect) +
						xn.taggedValues();
			}
		}
		if (point->reasons) {
			const BIT_STRING_BITNAME *pbn;
			QStringList r;
			for (pbn = reason_flags; pbn->lname; pbn++) {
				if (ASN1_BIT_STRING_get_bit(point->reasons,
								pbn->bitnum))
					r += pbn->sname;
			}
			crldpsect += "reasons=" + r.join(", ") + "\n";
		}
		if (point->CRLissuer) {
			QString ret;
			if (genNameStack2conf(point->CRLissuer,
					tag +"_crlissuer", &ret, &othersect))
				goto could_not_parse;
			crldpsect += "CRLissuer=" + ret + "\n";
		}
		crldps << tag;
		othersect = crldpsect + othersect;
	}
	ext_str_free(ext, crld);
	if (crldps.size() == 0)
		return true;
	*adv = "crlDistributionPoints=" + parse_critical() +
		crldps.join(", ") + "\n" + *adv + othersect;
	return true;

could_not_parse:
#endif
	ext_str_free(ext, crld);
	return false;
}

static void gen_cpol_notice(QString tag, USERNOTICE *notice, QString *adv)
{
	*adv += QString("\n[%1]\n").arg(tag);
	if (notice->exptext) {
		*adv += QString("explicitText=%1\n").
				arg(asn1ToQString(notice->exptext, true));
	}
	if (notice->noticeref) {
		NOTICEREF *ref = notice->noticeref;
		QStringList sl;
		int i;
		*adv += QString("organization=%1\n").
                                arg(asn1ToQString(ref->organization, true));
		for (i = 0; i < sk_ASN1_INTEGER_num(ref->noticenos); i++) {
			a1int num(sk_ASN1_INTEGER_value(ref->noticenos, i));
			sl << num.toDec();
                }
		if (sl.size())
			*adv += QString("noticeNumbers=%1\n").
					arg(sl.join(", "));
	}
}

static bool gen_cpol_qual_sect(QString tag, POLICYINFO *pinfo, QString *adv)
{
	QString polsect = QString("\n[%1]\n").arg(tag);
	QString noticetag;
	STACK_OF(POLICYQUALINFO) *quals = pinfo->qualifiers;
	int i;

	polsect += QString("policyIdentifier=%1\n").
			arg(OBJ_obj2QString(pinfo->policyid));

	for (i = 0; i < sk_POLICYQUALINFO_num(quals); i++) {
		POLICYQUALINFO *qualinfo = sk_POLICYQUALINFO_value(quals, i);
                switch (OBJ_obj2nid(qualinfo->pqualid)) {
		case NID_id_qt_cps:
			polsect += QString("CPS.%1=%2\n").arg(i).
					arg(asn1ToQString(qualinfo->d.cpsuri, true));
			break;
		case NID_id_qt_unotice:
			noticetag = QString("%1_notice%2_sect").arg(tag).arg(i);
			polsect += QString("userNotice.%1=@%2\n").arg(i).
					arg(noticetag);
			gen_cpol_notice(noticetag, qualinfo->d.usernotice, adv);
			break;
		default:
			return false;
		}
	}
	*adv = polsect + *adv;
	return true;
}


bool x509v3ext::parse_certpol(QString *single, QString *adv) const
{
	bool retval = true;
	QStringList pols;
	QString myadv;
	STACK_OF(POLICYINFO) *pol = (STACK_OF(POLICYINFO) *)ext_str_new(ext);
	int i;
	for (i = 0; i < sk_POLICYINFO_num(pol); i++) {
		POLICYINFO *pinfo = sk_POLICYINFO_value(pol, i);
		if (!pinfo->qualifiers) {
			pols << OBJ_obj2QString(pinfo->policyid);
			continue;
		}
		QString tag = QString("certpol%1_sect").arg(i);
		pols << QString("@") + tag;
		if (!gen_cpol_qual_sect(tag, pinfo, &myadv)) {
			retval = false;
			break;
		}
	}
	if (retval)
		*adv = QString("certificatePolicies=ia5org,%1\n").
		arg(pols.join(", ")) + *adv + myadv;
	ext_str_free(ext, pol);
	return retval;
}

bool x509v3ext::parse_bc(QString *single, QString *adv) const
{
	BASIC_CONSTRAINTS *bc = (BASIC_CONSTRAINTS *)ext_str_new(ext);
	QString ret = a1int(bc->pathlen).toDec();
	if (!ret.isEmpty())
		ret = ",pathlen:" + ret;
	ret = parse_critical() + (bc->ca ? "CA:FALSE" : "CA:TRUE") + ret;
	if (single)
		*single = ret;
	if (adv)
		*adv = QString("%1=%2").arg(OBJ_nid2sn(nid())).arg(*adv);
	return true;
}

bool x509v3ext::genConf(QString *single, QString *adv) const
{
	int n = nid();
	switch (n) {
	case NID_crl_distribution_points:
		return parse_Crldp(single, adv);
	case NID_subject_alt_name:
	case NID_issuer_alt_name:
		return parse_generalName(single, adv);
	case NID_info_access:
		return parse_ainfo(single, adv);
	case NID_ext_key_usage:
		return parse_eku(single, adv);
	case NID_certificate_policies:
		return parse_certpol(single, adv);
	case NID_netscape_comment:
	case NID_netscape_base_url:
	case NID_netscape_revocation_url:
	case NID_netscape_ca_revocation_url:
	case NID_netscape_renewal_url:
	case NID_netscape_ca_policy_url:
	case NID_netscape_ssl_server_name:
		return parse_i2s(single, adv);
	case NID_basic_constraints:
		return parse_bc(single, adv);
	}
	return false;
}

QString x509v3ext::getHtml() const
{
	QString html;
	html = "<b><u>" + getObject();
	if (getCritical() != 0)
		html += " <font color=\"red\">critical</font>";
	html += ":</u></b><br><tt>" + getValue(true) + "</tt>";
	return html;
}

X509_EXTENSION *x509v3ext::get() const
{
	return X509_EXTENSION_dup(ext);
}

bool x509v3ext::isValid() const
{
	return ext->value->length > 0 &&
		OBJ_obj2nid(ext->object) != NID_undef;
}

/*************************************************************/

bool extList::genConf(int nid, QString *single, QString *adv)
{
	int i = idxByNid(nid);
	if (i != -1) {
		if (at(i).genConf(single, adv))
			removeAt(i);
		ign_openssl_error();
		return true;
	}
	return false;
}

void extList::setStack(STACK_OF(X509_EXTENSION) *st, int start)
{
	clear();
	int cnt = sk_X509_EXTENSION_num(st);
	x509v3ext e;
	for (int i=start; i<cnt; i++) {
		e.set(sk_X509_EXTENSION_value(st,i));
		append(e);
	}
}

STACK_OF(X509_EXTENSION) *extList::getStack()
{
	STACK_OF(X509_EXTENSION) *sk;
	sk = sk_X509_EXTENSION_new_null();
	for (int i=0; i< count(); i++) {
		sk_X509_EXTENSION_push(sk, operator[](i).get());
	}
	return sk;
}

QString extList::getHtml(const QString &sep)
{
	x509v3ext e;
	QStringList s;
	for (int i=0; i< size(); i++)
		s << at(i).getHtml();
	QString a = s.join(sep);
	return a;
}

bool extList::delByNid(int nid)
{
	for(int i = 0; i< size(); i++) {
		if (at(i).nid() == nid) {
			removeAt(i);
			return true;
		}
	}
	return false;
}

int extList::idxByNid(int nid)
{
	for(int i = 0; i< size(); i++) {
		if (at(i).nid() == nid) {
			return i;
		}
	}
	return -1;
}

int extList::delInvalid(void)
{
	int removed=0;
	for(int i = 0; i<size(); i++) {
		if (!at(i).isValid()) {
			removeAt(i);
			removed=1;
			i--;
		}
	}
	return removed;
}
