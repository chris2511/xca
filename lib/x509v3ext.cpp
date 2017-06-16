/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509v3ext.h"
#include "x509name.h"
#include "asn1int.h"
#include "func.h"
#include "exception.h"
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <QStringList>
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
	ASN1_OCTET_STRING *str = n.getData();
	ext = X509_EXTENSION_new();
	if (str && str->length)
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
		QByteArray ba = et.toLocal8Bit();
		ext = X509V3_EXT_conf_nid(NULL, ctx, nid, ba.data());
	}
	if (!ext)
		ext = X509_EXTENSION_new();
	else {
		if (ctx && ctx->subject_cert) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			X509_add_ext(ctx->subject_cert, ext, -1);
#else
			STACK_OF(X509_EXTENSION) **sk;
			sk = &ctx->subject_cert->cert_info->extensions;
			X509v3_add_ext(sk, ext, -1);
#endif
		}
	}
	return *this;
}

x509v3ext &x509v3ext::create_ia5(int nid, const QString &et, X509V3_CTX *ctx)
{
	QByteArray ba = et.toLocal8Bit();
	for (int i=0; i<ba.size(); i++) {
		if (ba[i] & 0x80)
			throw errorEx(QObject::tr("String '%1' for '%2' contains invalid characters").arg(et).arg(OBJ_nid2ln(nid)));
	}
	return create(nid, et, ctx);
}

const ASN1_OBJECT *x509v3ext::object() const
{
	ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
	try {
		openssl_error();
	} catch (errorEx e) {
		return NULL;
	}
	return obj;
}

int x509v3ext::nid() const
{
	const ASN1_OBJECT *obj = object();
	return obj ? OBJ_obj2nid(obj) : NID_undef;
}

void *x509v3ext::d2i() const
{
	void *r = X509V3_EXT_d2i(ext);
	ign_openssl_error();
	return r;
}

x509v3ext &x509v3ext::operator = (const x509v3ext &x)
{
	set(x.ext);
	return *this;
}

QString x509v3ext::getObject() const
{
	const ASN1_OBJECT *obj = object();
	return obj ? OBJ_obj2QString(obj) : QString("<ERROR>");
}

int x509v3ext::getCritical() const
{
	return X509_EXTENSION_get_critical(ext);
}

ASN1_OCTET_STRING *x509v3ext::getData() const
{
	return X509_EXTENSION_get_data(ext);
}

QString x509v3ext::getValue(bool html) const
{
	QString text = "";
	int ret;
	char *p = NULL;
	BIO *bio = BIO_new(BIO_s_mem());

	ret = X509V3_EXT_print(bio, ext, X509V3_EXT_DEFAULT, 0);
	if (ign_openssl_error() || !ret) {
		ret = ASN1_STRING_print(bio, (ASN1_STRING *) getData());
	}
	if (!ign_openssl_error() && ret) {
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

static QString obj2SnOid(const ASN1_OBJECT *a)
{
	QString obj;
	int nid = OBJ_obj2nid(a);

	if (nid == NID_undef)
		obj = OBJ_obj2QString(a);
	else
		obj = OBJ_nid2sn(nid);

	return obj;
}

static const char *asn1Type2Name(int type)
{
#define ASN1_GEN_STR(x,y) { x,y }
	struct {
	        const char *strnam;
		int tag;
	} tags[] = {
		ASN1_GEN_STR("BOOL", V_ASN1_BOOLEAN),
		ASN1_GEN_STR("NULL", V_ASN1_NULL),
		ASN1_GEN_STR("INT", V_ASN1_INTEGER),
		ASN1_GEN_STR("ENUM", V_ASN1_ENUMERATED),
		ASN1_GEN_STR("OID", V_ASN1_OBJECT),
		ASN1_GEN_STR("UTC", V_ASN1_UTCTIME),
		ASN1_GEN_STR("GENTIME", V_ASN1_GENERALIZEDTIME),
		ASN1_GEN_STR("OCT", V_ASN1_OCTET_STRING),
		ASN1_GEN_STR("BITSTR", V_ASN1_BIT_STRING),
		ASN1_GEN_STR("UNIV", V_ASN1_UNIVERSALSTRING),
		ASN1_GEN_STR("IA5", V_ASN1_IA5STRING),
		ASN1_GEN_STR("UTF8", V_ASN1_UTF8STRING),
		ASN1_GEN_STR("BMP", V_ASN1_BMPSTRING),
		ASN1_GEN_STR("VISIBLE", V_ASN1_VISIBLESTRING),
		ASN1_GEN_STR("PRINTABLE", V_ASN1_PRINTABLESTRING),
		ASN1_GEN_STR("T61", V_ASN1_T61STRING),
		ASN1_GEN_STR("GENSTR", V_ASN1_GENERALSTRING),
		ASN1_GEN_STR("NUMERIC", V_ASN1_NUMERICSTRING),
	};
	for (unsigned i=0; i< ARRAY_SIZE(tags); i++) {
		if (tags[i].tag == type)
			return tags[i].strnam;
	}
	return "UNKNOWN";
}

static bool asn1TypePrintable(int type)
{
	switch (type) {
	case V_ASN1_IA5STRING:
	case V_ASN1_UTF8STRING:
	case V_ASN1_BMPSTRING:
	case V_ASN1_VISIBLESTRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_T61STRING:
	case V_ASN1_GENERALSTRING:
		return true;
	}
	return false;
}

static QString ipv6_from_binary(const unsigned char *p)
{
	QString ip;
	int i, skip =0, skiplen = 0, skippos =0;

	/* find largest gap */
	for (i = 0; i < 17; i += 2) {
		if (i==16 || (p[i] | p[i +1])) {
			if (skiplen < skip) {
				skiplen = skip;
				skippos = i - skip;
			}
			skip = 0;
		} else {
			skip += 2;
		}
	}
	for (i = 0, skip = 0; i < 16; i += 2) {
		int x = p[i] << 8 | p[i+1];
		skip += skippos == i;
		switch (!x*4 + skip) {
		case 5: // skip first 0
			skip = 2;
			ip += ":";
		case 6: // skip next 0
			break;
		default: // no reduction
			skip = 0;
			ip += QString("%1%2").arg(i? ":" : "").arg(x,0,16);
		}
	}
	if (skip == 2)
		ip += ":";
	return ip;
}

static bool
genName2conf(GENERAL_NAME *gen, QString tag, QString *single, QString *sect)
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
		return true;
	}
	case GEN_IPADD:
		p = gen->d.ip->data;
		if (gen->d.ip->length == 4) {
			*single = QString("IP:%1.%2.%3.%4").
				arg(p[0]).arg(p[1]).arg(p[2]).arg(p[3]);
			return true;
		} else if(gen->d.ip->length == 8) {
			 *single = QString("IP:%1.%2.%3.%4/%5.%6.%7.%8").
                                arg(p[0]).arg(p[1]).arg(p[2]).arg(p[3]).
                                arg(p[4]).arg(p[5]).arg(p[6]).arg(p[7]);
                        return true;
		} else if(gen->d.ip->length == 16) {
			*single = "IP:" + ipv6_from_binary(gen->d.ip->data);
			return true;
		} else if(gen->d.ip->length == 32) {
			*single = "IP:" + ipv6_from_binary(gen->d.ip->data) +
				"/" + ipv6_from_binary(gen->d.ip->data +16);
			return true;
		}
		return false;

	case GEN_RID:
		*single = QString("RID:%1").
				arg(obj2SnOid(gen->d.rid));
		return true;
	case GEN_OTHERNAME: {
		int type = gen->d.otherName->value->type;
		ASN1_STRING *a;
		a = gen->d.otherName->value->value.asn1_string;
		if (asn1TypePrintable(type)) {
			*single = QString("otherName:%1;%2:%3").
			arg(obj2SnOid(gen->d.otherName->type_id)).
			arg(asn1Type2Name(type)).
			arg(asn1ToQString(a, true));
		} else {
			*single = QString("otherName:%1;FORMAT:HEX,%2").
			arg(obj2SnOid(gen->d.otherName->type_id)).
			arg(asn1Type2Name(type));
			for (int i=0; i<a->length; i++) {
				*single += QString(":%1").
				arg((int)(a->data[i]), 2, 16, QChar('0'));
			}
		}
		return true;
	}
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

#define TEXTS (\
	B_ASN1_TIME | B_ASN1_DIRECTORYSTRING | B_ASN1_DISPLAYTEXT | \
	B_ASN1_NUMERICSTRING | B_ASN1_T61STRING | B_ASN1_UNIVERSALSTRING)

bool x509v3ext::parse_ia5(QString *single, QString *adv) const
{
	ASN1_STRING *str = (ASN1_STRING *)d2i();
	QString ret;

	if (!str) {
		const unsigned char *p = getData()->data;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		long len;
		int tag, xclass;
		if (ASN1_get_object(&p, &len, &tag, &xclass, getData()->length) & 0x80)
			return false;
		if (tag >= 32)
			return false;
		if (!(ASN1_tag2bit(tag) & TEXTS))
			return false;
		if (!(str = ASN1_STRING_type_new(tag)))
			return false;
		if (!ASN1_STRING_set(str, p, len)) {
			ASN1_STRING_free(str);
			return false;
		}
#else
		str = d2i_ASN1_type_bytes(NULL, &p, getData()->length, TEXTS);
#endif
		if (ign_openssl_error() || !str)
			return false;
		ret = QString("<ERROR: NOT IA5 but %1>%2").
			arg(asn1Type2Name(str->type)).
			arg(QString(asn1ToQString(str)));
	} else {
		ret = QString(asn1ToQString(str));
	}
	if (single)
		*single = ret;
	else if (adv)
		*adv = QString("%1=%2\n").arg(OBJ_nid2sn(nid())).arg(ret) +*adv;

	ASN1_STRING_free(str);
	return true;
}

bool x509v3ext::parse_generalName(QString *single, QString *adv) const
{
	bool retval = true;
	QString sect, ret;
	STACK_OF(GENERAL_NAME) *gens = (STACK_OF(GENERAL_NAME) *)d2i();

	if (!gens)
		return false;

	QString tag = OBJ_nid2sn(nid());

	if (!genNameStack2conf(gens, tag, &ret, &sect))
		retval = false;
	else if (sect.isEmpty() && single) {
		*single = parse_critical() + ret;
	} else if (adv) {
		*adv = QString("%1=%2\n").arg(tag).
			arg(parse_critical() +ret) + *adv + sect;
	}
	sk_GENERAL_NAME_free(gens);
	return retval;
}

bool x509v3ext::parse_eku(QString *single, QString *adv) const
{
	EXTENDED_KEY_USAGE *eku = (EXTENDED_KEY_USAGE *)d2i();
	QStringList sl;
	int i;

	if (!eku)
		return false;

	for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
		sl << QString(OBJ_obj2sn(sk_ASN1_OBJECT_value(eku, i)));
	}
	QString r = parse_critical() + sl.join(", ");
	if (single)
		*single = r;
	else if (adv)
		*adv = QString("%1=%2\n").arg(OBJ_nid2sn(nid())).arg(r) + *adv;

	EXTENDED_KEY_USAGE_free(eku);
	return true;
}

bool x509v3ext::parse_ainfo(QString *single, QString *adv) const
{
	bool retval = true;
	QString sect, ret;
        QString tag = OBJ_nid2sn(nid());
	QStringList sl;
	int i;

	AUTHORITY_INFO_ACCESS *ainfo = (AUTHORITY_INFO_ACCESS *)d2i();

	if (!ainfo)
		return false;

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
		if (sect.isEmpty() && sk_ACCESS_DESCRIPTION_num(ainfo) == 1 && single) {
			*single = parse_critical() + ret;
		} else if (adv) {
			*adv = QString("%1=%2\n").arg(tag).
				arg(parse_critical() + ret) + *adv + sect;
		}
	}
	AUTHORITY_INFO_ACCESS_free(ainfo);
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

static QString parse_bits(const BIT_STRING_BITNAME *flags,
				ASN1_BIT_STRING *str)
{
	const BIT_STRING_BITNAME *pbn;
	QStringList r;
	for (pbn = flags; pbn->sname; pbn++) {
		if (ASN1_BIT_STRING_get_bit(str, pbn->bitnum))
			r << QString(pbn->sname);
	}
	return r.join(", ");
}

bool x509v3ext::parse_Crldp(QString *single, QString *adv) const
{
	QString othersect;
	QStringList crldps;
	const char *sn = OBJ_nid2sn(nid());

	STACK_OF(DIST_POINT) *crld = (STACK_OF(DIST_POINT)*)d2i();

	if (!crld)
		return false;

	if (sk_DIST_POINT_num(crld) == 1 && single) {
		DIST_POINT *point = sk_DIST_POINT_value(crld, 0);
		if (point->distpoint && !point->reasons && !point->CRLissuer &&
		    !point->distpoint->type)
		{
			QString sect, ret;
			if (!genNameStack2conf(point->distpoint->name.fullname,
						"", &ret, &sect))
				goto could_not_parse;

			if (sect.isEmpty()) {
				if (single)
					*single = parse_critical() +ret;
				else if (adv)
					*adv = QString("%1=%2\n").arg(sn).
					       arg(parse_critical() +ret) +*adv;
				return true;
			}
		}
	}
	for(int i = 0; i < sk_DIST_POINT_num(crld); i++) {
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
			crldpsect += QString("reasons=%1\n").
				arg(parse_bits(reason_flags, point->reasons));
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
	sk_DIST_POINT_free(crld);
	if (crldps.size() == 0)
		return true;
	if (adv) {
		*adv = QString("%1=%2\n").arg(sn).
			arg(parse_critical() + crldps.join(", ")) +
			*adv + othersect;

#if OPENSSL_VERSION_NUMBER < 0x10000000L
		*adv = QString( "\n"
			"# This syntax only works for openssl >= 1.0.0\n"
			"# But this is %1\n"
			"# ").arg(OPENSSL_VERSION_TEXT) + *adv;
#endif
	}
	return true;

could_not_parse:
	sk_DIST_POINT_free(crld);
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
	QString noticetag, _adv;
	STACK_OF(POLICYQUALINFO) *quals = pinfo->qualifiers;
	int i;

	if (!quals)
		return false;

	if (!adv)
		adv = &_adv;

	polsect += QString("policyIdentifier=%1\n").
			arg(obj2SnOid(pinfo->policyid));

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


bool x509v3ext::parse_certpol(QString *, QString *adv) const
{
	bool retval = true;
	QStringList pols;
	QString myadv;
	int i;
	STACK_OF(POLICYINFO) *pol = (STACK_OF(POLICYINFO) *)d2i();

	if (!pol)
		return false;

	for (i = 0; i < sk_POLICYINFO_num(pol); i++) {
		POLICYINFO *pinfo = sk_POLICYINFO_value(pol, i);
		if (!pinfo->qualifiers) {
			pols << obj2SnOid(pinfo->policyid);
			continue;
		}
		QString tag = QString("certpol%1_sect").arg(i);
		pols << QString("@") + tag;
		if (!gen_cpol_qual_sect(tag, pinfo, &myadv)) {
			retval = false;
			break;
		}
	}
	if (retval && adv)
		*adv = QString("certificatePolicies=%1ia5org,%2\n").
		arg(parse_critical()).arg(pols.join(", ")) + *adv + myadv;
	sk_POLICYINFO_free(pol);
	return retval;
}

bool x509v3ext::parse_bc(QString *single, QString *adv) const
{
	BASIC_CONSTRAINTS *bc = (BASIC_CONSTRAINTS *)d2i();

	if (!bc)
		return false;

	QString ret = a1int(bc->pathlen).toDec();
	if (!ret.isEmpty())
		ret = ",pathlen:" + ret;
	ret = parse_critical() + (bc->ca ? "CA:TRUE" : "CA:FALSE") + ret;
	if (single)
		*single = ret;
	else if (adv)
		*adv = QString("%1=%2\n").arg(OBJ_nid2sn(nid())).arg(ret) +*adv;
	BASIC_CONSTRAINTS_free(bc);
	return true;
}

static const BIT_STRING_BITNAME key_usage_type_table[] = {
{0, "Digital Signature", "digitalSignature"},
{1, "Non Repudiation", "nonRepudiation"},
{2, "Key Encipherment", "keyEncipherment"},
{3, "Data Encipherment", "dataEncipherment"},
{4, "Key Agreement", "keyAgreement"},
{5, "Certificate Sign", "keyCertSign"},
{6, "CRL Sign", "cRLSign"},
{7, "Encipher Only", "encipherOnly"},
{8, "Decipher Only", "decipherOnly"},
{-1, NULL, NULL}
};

static const BIT_STRING_BITNAME ns_cert_type_table[] = {
{0, "SSL Client", "client"},
{1, "SSL Server", "server"},
{2, "S/MIME", "email"},
{3, "Object Signing", "objsign"},
{4, "Unused", "reserved"},
{5, "SSL CA", "sslCA"},
{6, "S/MIME CA", "emailCA"},
{7, "Object Signing CA", "objCA"},
{-1, NULL, NULL}
};

bool x509v3ext::parse_bitstring(QString *single, QString *adv) const
{
	ASN1_BIT_STRING *bs;
	const BIT_STRING_BITNAME *bnames;
	int n = nid();

	switch (n) {
	case NID_key_usage: bnames = key_usage_type_table; break;
	case NID_netscape_cert_type: bnames = ns_cert_type_table; break;
	default: return false;
	}
	bs = (ASN1_BIT_STRING *)d2i();

	if (!bs)
		return false;

	QString ret = parse_critical() + parse_bits(bnames, bs);
	if (single)
		*single = ret;
	else if (adv)
		*adv = QString("%1=%2\n").arg(OBJ_nid2sn(nid())).arg(ret) +*adv;
	ASN1_BIT_STRING_free(bs);
        return true;
}

bool x509v3ext::parse_sKeyId(QString *, QString *adv) const
{
	if (adv)
		*adv = QString("%1=hash\n").arg(OBJ_nid2sn(nid())) + *adv;
	return true;
}

bool x509v3ext::parse_aKeyId(QString *, QString *adv) const
{
	QStringList ret;
	AUTHORITY_KEYID *akeyid = (AUTHORITY_KEYID *)d2i();

	if (!akeyid)
		return false;

	if (akeyid->keyid)
		ret << "keyid";
	if (akeyid->issuer)
		ret << "issuer";
	if (adv)
		*adv = QString("%1=%2\n").arg(OBJ_nid2sn(nid())).
			arg(ret.join(", ")) + *adv;
	AUTHORITY_KEYID_free(akeyid);
	return true;
}

bool x509v3ext::parse_generic(QString *, QString *adv) const
{
	const ASN1_OBJECT *o = object();
	QString der, obj = o ? obj2SnOid(o) : QString("<ERROR>");
	ASN1_OCTET_STRING *v = getData();

	for (int i=0; i<v->length; i++)
		der += QString(":%1").arg((int)(v->data[i]), 2, 16, QChar('0'));

	if (adv)
		*adv = QString("%1=%2DER%3\n").arg(obj).
				arg(parse_critical()).arg(der) +
			*adv;
	return true;
}

bool x509v3ext::parse_inhibitAnyPolicy(QString *, QString *adv) const
{
	ASN1_INTEGER *a = (ASN1_INTEGER *)d2i();

	if (!a)
		return false;

	a1int val(a);
	if (adv) {
		*adv = QString("%1=%2%3\n").arg(OBJ_nid2sn(nid())).
			arg(parse_critical()).arg(val.toDec()) + *adv;
	}
	ASN1_INTEGER_free(a);
	return true;
}

bool x509v3ext::parse_policyConstraints(QString *, QString *adv) const
{
	QStringList v;
	a1int a1null(0L), a;
	POLICY_CONSTRAINTS *pol = (POLICY_CONSTRAINTS *)d2i();

	if (!pol)
		return false;

	a = a1int(pol->requireExplicitPolicy);
	if (a != a1null)
		v << QString("requireExplicitPolicy:%1").arg(a.toDec());

	a = a1int(pol->inhibitPolicyMapping);
	if (a != a1null)
		v << QString("inhibitPolicyMapping:%1").arg(a.toDec());

	if (adv)
		*adv = QString("%1=%2%3\n").arg(OBJ_nid2sn(nid())).
			arg(parse_critical()).arg(v.join(", ")) + *adv;
	POLICY_CONSTRAINTS_free(pol);
	return true;

}

bool x509v3ext::parse_policyMappings(QString *, QString *adv) const
{
	bool retval = true;
	QStringList polMaps;
	QString myadv;
	POLICY_MAPPINGS *pmaps = (POLICY_MAPPINGS *)d2i();

	if (!pmaps)
		return false;

	for (int i = 0; i < sk_POLICY_MAPPING_num(pmaps); i++) {
		POLICY_MAPPING *pmap = sk_POLICY_MAPPING_value(pmaps, i);
		polMaps << QString("%1 = %2").
			arg(obj2SnOid(pmap->issuerDomainPolicy)).
			arg(obj2SnOid(pmap->subjectDomainPolicy));
	}
	if (polMaps.size() > 0 && adv) {
		*adv = QString("policyMappings=%1@policyMappings_sect\n").
		arg(parse_critical()) + *adv +
		QString("[policyMappings_sect]\n") + polMaps.join("\n");
	}
	sk_POLICY_MAPPING_free(pmaps);
	return retval;
}

static bool nameConstraint(STACK_OF(GENERAL_SUBTREE) *trees,
		QString prefix, QString tag, QString *single, QString *sect)
{
	QStringList sl;
	for (int i = 0; i < sk_GENERAL_SUBTREE_num(trees); i++) {
		QString one;
		GENERAL_SUBTREE *tree = sk_GENERAL_SUBTREE_value(trees, i);
		if (!genName2conf(tree->base,
			QString("%1_%2").arg(tag).arg(i), &one, sect))
		{
			return false;
		}
		fprintf(stderr, "%s: %d '%s'\n", __func__, i, CCHAR(one));
		sl << prefix + ";" + one;
	}
	*single = vlist2Section(sl, tag+prefix, sect);
	fprintf(stderr, "Single: '%s'\n", CCHAR(*single));
	return true;
}

bool x509v3ext::parse_nameConstraints(QString *, QString *adv) const
{
	bool retval = true;
	QString sect, ret;
	QStringList permEx;
	QString tag = OBJ_nid2sn(nid());
	NAME_CONSTRAINTS *cons = (NAME_CONSTRAINTS *)d2i();

	if (!cons)
		return false;

	if (!nameConstraint(cons->permittedSubtrees, "permitted",
				tag, &ret, &sect))
		retval = false;
	if (ret.size() > 0)
		permEx << ret;
	if (!nameConstraint(cons->excludedSubtrees, "excluded",
				tag, &ret, &sect))
		retval = false;
	if (ret.size() > 0)
		permEx << ret;

	if (adv && retval &&permEx.size() > 0) {
		ret = permEx.join(", ");
		fprintf(stderr, "%s %d '%s'\n", __func__, retval, CCHAR(ret));
		*adv = QString("%1=%2\n").arg(tag).
			arg(parse_critical() +ret) + *adv + sect;
	}
	NAME_CONSTRAINTS_free(cons);
	return retval;
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
		return parse_ia5(single, adv);
	case NID_basic_constraints:
		return parse_bc(single, adv);
	case NID_key_usage:
	case NID_netscape_cert_type:
		return parse_bitstring(single, adv);
	case NID_subject_key_identifier:
		return parse_sKeyId(single, adv);
	case NID_authority_key_identifier:
		return parse_aKeyId(single, adv);
	case NID_inhibit_any_policy:
		return parse_inhibitAnyPolicy(single, adv);
	case NID_policy_constraints:
		return parse_policyConstraints(single, adv);
	case NID_policy_mappings:
		return parse_policyMappings(single, adv);
	case NID_name_constraints:
		return parse_nameConstraints(single, adv);
	case NID_id_pkix_OCSP_noCheck:
		if (adv)
			*adv = "noCheck = ignored\n" + *adv;
		return true;
	default:
		return parse_generic(single, adv);
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
	return ext && getData() && getData()->length > 0 &&
		OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_undef;
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

void extList::genGenericConf(QString *adv)
{
	for (int i=0; i< size();) {
		if (at(i).genConf(NULL, adv) || at(i).parse_generic(NULL, adv))
			removeAt(i);
		else
			i++;
		ign_openssl_error();
	}
}

void extList::setStack(const STACK_OF(X509_EXTENSION) *st, int start)
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

bool extList::search(const QRegExp &pattern)
{
	for (int i=0; i < size(); i++)
		if (at(i).getValue(false).contains(pattern))
			return true;
	return false;
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
