/* base definitions */

#ifdef WIN32
#define VER "0.2.10-W32"
#endif

#define MARK CERR("--Mark--")
#define DBEX(x) CERR("DB-error: "<<x.what()<<", Errno: "<<x.get_errno())

#ifdef PRINTF_DEBUG
#define CERR(x) cerr <<__FILE__<<" ("<<__LINE__<<") :"<< x << endl;
#else
#define CERR(x)
#endif


#define XCA_TITLE "X Certifikate and Key management"
