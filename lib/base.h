/* base definitions */

#ifdef WIN32
#define VER "0.2.7-W32"
#endif

#define MARK CERR("--Mark--")

#ifdef PRINTF_DEBUG
#define CERR(x) cerr <<__FILE__<<" ("<<__LINE__<<") :"<< x << endl;
#else
#define CERR(x)
#endif


#define XCA_TITLE "X Certifikate and Key management"
