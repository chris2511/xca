/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __HEADERLIST_H
#define __HEADERLIST_H

#include <QString>
#include <QList>
#include <QAction>
#include <QHeaderView>
#include <openssl/objects.h>
#include "db.h"
#include "func.h"

#define HD_undef NID_undef
#define HD_internal_name -2
#define HD_subject_name -3
#define HD_subject_hash -4
#define HD_x509key_name -5
#define HD_counter -6
#define HD_x509_sigalg -7

#define HD_cert_serial -10
#define HD_cert_notBefore -11
#define HD_cert_notAfter -12
#define HD_cert_trust -13
#define HD_cert_revocation -14
#define HD_cert_ca	 -15
#define HD_cert_md5fp	 -16
#define HD_cert_sha1fp   -17
#define HD_cert_sha256fp -18
#define HD_cert_crl_expire -19

#define HD_req_signed -20
#define HD_req_unstr_name -21
#define HD_req_chall_pass -22
#define HD_temp_type -30

#define HD_crl_signer -40
#define HD_crl_revoked -42
#define HD_crl_lastUpdate -43
#define HD_crl_nextUpdate -44
#define HD_crl_crlnumber  -45

#define HD_key_type -50
#define HD_key_size -51
#define HD_key_use  -52
#define HD_key_passwd -53
#define HD_key_curve -54

class dbheader
{
    protected:
	void init()
	{
		id = HD_undef;
		action = NULL;
		show = showDefault = false;
		size = -1;
		visualIndex = -1;
		sortIndicator = -1;
		type = hd_default;
	}
	QString name, tooltip;

    public:
	enum hdr_type {
		hd_default,
		hd_x509name,
		hd_v3ext,
		hd_v3ext_ns,
	};
	int id;
	bool show;
	bool showDefault;
	virtual QString getName() { return name; }
	virtual QString getTooltip() { return tooltip; }
	QAction *action;
	int size;
	int visualIndex;
	int sortIndicator;
	enum hdr_type type;

#if 1
	dbheader(QString aname = QString())
	{
		init();
		name = aname;
	}
#endif
	dbheader(int aid, bool ashow,
		QString aname = QString(), QString atip = QString())
	{
		init();
		id = aid;
		name = aname;
		tooltip = atip;
		show = showDefault = ashow;
	}
	virtual ~dbheader() { }

	bool mustSave()
	{
		return  size != -1 ||
			visualIndex != -1 ||
			sortIndicator != -1 ||
			show != showDefault;
	}
	bool operator == (const dbheader *h) const
	{
		if (h->id == HD_undef)
			return name == h->name;
		return id == h->id;
	}
	bool isNumeric()
	{
		switch (id) {
		case HD_counter:
		case HD_key_size:
		case HD_key_use:
		case HD_cert_serial:
		case HD_crl_revoked:
		case HD_crl_crlnumber:
		case HD_subject_hash:
		case HD_cert_md5fp:
		case HD_cert_sha1fp:
		case HD_cert_sha256fp:
		case NID_subject_key_identifier:
		case NID_authority_key_identifier:
			return true;
		}
		return false;
	}
	QByteArray toData()
	{
		QByteArray ba;
		ba += db::intToData(visualIndex);
		ba += db::intToData(sortIndicator);
		ba += db::intToData(size);
		ba += db::boolToData(show);
		return ba;
	}
	void fromData(QByteArray &ba)
	{
		visualIndex = db::intFromData(ba);
		sortIndicator = db::intFromData(ba);
		size = db::intFromData(ba);
		show = db::boolFromData(ba);
	}
	void setupHeaderView(int sect, QHeaderView *hv)
	{
		hv->setSectionHidden(sect, !show);
		if (size != -1)
			hv->resizeSection(sect, size);
		if (sortIndicator != -1) {
			hv->setSortIndicator(sect, sortIndicator ?
				Qt::DescendingOrder : Qt::AscendingOrder);
		}
	}
	void reset()
	{
		action = NULL;
		show = showDefault;
		size = -1;
		visualIndex = -1;
		sortIndicator = -1;
	}
};

class nid_dbheader : public dbheader
{
    private:
	QString sn;

    public:
	nid_dbheader(int aid, enum hdr_type atype)
		: dbheader(aid, aid == NID_commonName)
	{
		type = atype;
		tooltip = dn_translations[id];
		name = OBJ_nid2ln(id);
		sn = OBJ_nid2sn(id);
		if (tooltip.isEmpty())
			tooltip = name;
	}
	QString getName()
	{
		return translate_dn ? tooltip : name;
	}
	QString getTooltip()
	{
		return QString("[%1] %2").arg(sn)
			.arg(translate_dn ? name : tooltip);
	}
};

class dbheaderList: public QList<dbheader*>
{
    public:

	dbheaderList(dbheader *h) :QList<dbheader*>() {
		append(h);
	}
	dbheaderList() :QList<dbheader*>() {
	}
	QByteArray toData()
	{
		QByteArray ba;
		for (int i=0; i<count(); i++) {
			dbheader *h = at(i);
			if (!h->mustSave())
				continue;
			ba += db::intToData(h->id);
			if (h->id > 0) {
				ASN1_OBJECT *o = OBJ_nid2obj(h->id);
				ba += i2d_bytearray(I2D_VOID(i2d_ASN1_OBJECT), o);
			}
			ba += h->toData();
		}
		return ba;
	}
	void fromData(QByteArray &ba)
	{
		while (ba.size()) {
			int id = db::intFromData(ba);
			if (id > 0) {
				ASN1_OBJECT *o = (ASN1_OBJECT*)d2i_bytearray(D2I_VOID(d2i_ASN1_OBJECT), ba);
				id = OBJ_obj2nid(o);
				ASN1_OBJECT_free(o);
			}
			for (int i=0; i<count(); i++) {
				dbheader *h = at(i);
				if (h->id == id) {
					h->fromData(ba);
					id = 0;
					break;
				}
			}
			if (id != 0) {
				dbheader h("dummy");
				h.fromData(ba);
			}
		}
	}
};
#endif
