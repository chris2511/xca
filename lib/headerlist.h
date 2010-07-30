
#include <QtCore/QString>
#include <QtCore/QList>
#include <QtGui/QAction>
#include <openssl/objects.h>

#define HD_undef NID_undef
#define HD_internal_name -2
#define HD_subject_name -3

#define HD_cert_serial -10
#define HD_cert_notBefore -11
#define HD_cert_notAfter -12
#define HD_cert_trust -13
#define HD_cert_revokation -14
#define HD_cert_ca	 -15
#define HD_cert_md5fp	 -16
#define HD_cert_sha1fp   -17

#define HD_req_signed -20
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
    public:
	int id;
	bool show;
	bool showDefault;
	QString name;
	QString tooltip;
	QAction *action;
	dbheader(QString aname = QString())
	{
		id = HD_undef;
		name = aname;
		action = NULL;
		show = showDefault = false;
	}
	dbheader(int aid, bool ashow = false,
		QString aname = QString(), QString atip = QString())
	{
		id = aid;
		name = aname;
		tooltip = atip;
		if (isNid() && name.isEmpty()) {
			name = OBJ_nid2ln(aid);
			tooltip = OBJ_nid2sn(aid);
		}
		action = NULL;
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
			return true;
		}
		return false;
	}
};

typedef QList<dbheader*> dbheaderList;
