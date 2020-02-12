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
#include <QDebug>
#include <openssl/objects.h>
#include "db.h"
#include "settings.h"
#include "func.h"

#define HD_undef NID_undef
#define HD_internal_name -2
#define HD_subject_name -3
#define HD_subject_hash -4
#define HD_x509key_name -5
#define HD_counter -6
#define HD_x509_sigalg -7
#define HD_creation -8
#define HD_comment -9
#define HD_source -100
#define HD_primary_key -101

#define HD_cert_serial -10
#define HD_cert_notBefore -11
#define HD_cert_notAfter -12
//#define HD_cert_trust -13
#define HD_cert_revocation -14
#define HD_cert_ca	 -15
#define HD_cert_md5fp	 -16
#define HD_cert_sha1fp   -17
#define HD_cert_sha256fp -18
#define HD_cert_crl_expire -19

#define HD_req_signed -20
#define HD_req_unstr_name -21
#define HD_req_chall_pass -22
#define HD_req_certs -23
//#define HD_temp_type -30

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
		hd_number,
		hd_asn1time,
		hd_key,
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

	dbheader(QString aname = QString())
	{
		init();
		name = aname;
	}
	dbheader(int aid, bool ashow = false,
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
		case NID_subject_key_identifier:
		case NID_authority_key_identifier:
		case HD_key_size:
			return true;
		}
		return type == hd_number;
	}
	QString toData()
	{
		QStringList sl; sl
		<< QString::number(visualIndex)
		<< QString::number(sortIndicator)
		<< QString::number(size)
		<< QString::number(show);
		return sl.join(" ");
	}
	void fromData(QString s)
	{
		QStringList sl = s.split(" ");
		if (sl.count() != 4) {
			qCritical() << "Invalid header data for" <<
					id << name << s;
			return;
		}
		visualIndex = sl[0].toInt();
		if (visualIndex < -1)
			visualIndex = -1;
		sortIndicator = sl[1].toInt();
		if (sortIndicator != Qt::AscendingOrder &&
		    sortIndicator != Qt::DescendingOrder)
			sortIndicator = -1;
		size = sl[2].toInt();
		if (size == 0)
			size = -1;
		show = sl[3].toInt();
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
		return Settings["translate_dn"] ? tooltip : name;
	}
	QString getTooltip()
	{
		return QString("[%1] %2").arg(sn)
			.arg(Settings["translate_dn"] ? name : tooltip);
	}
};

class num_dbheader : public dbheader
{
    public:
	num_dbheader(int aid, bool ashow = false,
		QString aname = QString(), QString atip = QString())
		: dbheader(aid, ashow, aname, atip)
	{
		type = hd_number;
	}
};

class date_dbheader : public dbheader
{
    public:
	date_dbheader(int aid, bool ashow = false,
		QString aname = QString(), QString atip = QString())
		: dbheader(aid, ashow, aname, atip)
	{
		type = hd_asn1time;
	}
};

class key_dbheader : public dbheader
{
    public:
	key_dbheader(int aid, QString aname)
		: dbheader(aid, false, aname)
	{
		type = hd_key;
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
	QString toData()
	{
		QStringList sl;
		for (int i=0; i<count(); i++) {
			QStringList seq;
			dbheader *h = at(i);
			if (!h->mustSave())
				continue;
			seq << QString("%1").arg(h->id);
			if (h->id > 0) {
				seq << OBJ_obj2QString(
					OBJ_nid2obj(h->id), 1);
			}
			seq << h->toData();
			sl << seq.join(":");
		}
		return sl.join(",");
	}
	void fromData(QString s)
	{
		QStringList sl = s.split(",");
		foreach(QString hd, sl) {
			QStringList sl1 = hd.split(":");
			int id = sl1.takeFirst().toInt();
			if (id > 0) {
				id = OBJ_txt2nid(CCHAR(sl1.takeFirst()));
			}
			for (int i=0; i<count(); i++) {
				dbheader *h = at(i);
				if (h->id == id) {
					h->fromData(sl1.takeFirst());
					break;
				}
			}
		}
	}
};
#endif
