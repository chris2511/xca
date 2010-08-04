
#include "db.h"
#include <QtCore/QString>
#include <QtCore/QList>
#include <QtGui/QAction>
#include <QtGui/QHeaderView>
#include <openssl/objects.h>

#define HD_undef NID_undef
#define HD_internal_name -2
#define HD_subject_name -3
#define HD_subject_hash -4
#define HD_x509key_name -5

#define HD_cert_serial -10
#define HD_cert_notBefore -11
#define HD_cert_notAfter -12
#define HD_cert_trust -13
#define HD_cert_revokation -14
#define HD_cert_ca	 -15
#define HD_cert_md5fp	 -16
#define HD_cert_sha1fp   -17

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

class dbheader
{
    private:
	void init()
	{
		id = HD_undef;
		action = NULL;
		show = showDefault = false;
		size = -1;
		visualIndex = -1;
		sortIndicator = -1;
	}
    public:
	int id;
	bool show;
	bool showDefault;
	QString name;
	QString tooltip;
	QAction *action;
	int size;
	int visualIndex;
	int sortIndicator;

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
		if (isNid() && name.isEmpty()) {
			name = OBJ_nid2ln(aid);
			tooltip = OBJ_nid2sn(aid);
		}
		show = showDefault = ashow;
	}
	bool operator == (const dbheader *h) const
	{
		if (h->id == HD_undef)
			return name == h->name;
		return id == h->id;
	}
	bool isNid() const
	{
		return (id > 0);
	}
	static bool isNid(int i)
	{
		return (i > 0);
	}
	bool isNumeric()
	{
		switch (id) {
		case HD_key_size:
		case HD_key_use:
		case HD_cert_serial:
		case HD_crl_revoked:
		case HD_crl_crlnumber:
		case HD_subject_hash:
		case HD_cert_md5fp:
		case HD_cert_sha1fp:
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

typedef QList<dbheader*> dbheaderList;
