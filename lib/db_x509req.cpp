#include "db_x509req.h"


db_x509req::db_x509req(DbEnv *dbe, string DBfile, string DB, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, DB, l)
{
	icon = new QPixmap("req.png");
	keylist = keyl;
	loadContainer();
	updateView();
}

pki_base *db_x509req::newPKI(){
	return new pki_x509req();
}

QStringList db_x509req::gethasPrivateDesc(db_base *keydb)
{
	pki_x509req *pki;
	pki_key *key, *refkey;
	QStringList x;
        if ( container.isEmpty() ) return x;
        for ( pki = (pki_x509req *)container.first(); pki != 0; pki = (pki_x509req *)container.next() ) {
		key = pki->getKey();
		if ((refkey = (pki_key *)keydb->findPKI(key))!= NULL) {
		   if (refkey->isPrivKey()){
			x.append(pki->getDescription().c_str());	
			cerr << "found" <<endl;
		   }
		}
	}
	return x;
}
