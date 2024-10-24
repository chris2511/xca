#include <QTextStream>
#include <QDebug>
#include <QByteArray>
#include <QFile>

#include "pki_export.h"

static const QMap<QString, pki_type> typeMap = {
    {"x509", x509},
    {"x509-clp", x509},
    {"key", asym_key},
    {"key-clp", asym_key},
    {"request", x509_req},
    {"revocation", revocation},
    {"template", tmpl},
};

static void noop(QtMsgType , const QMessageLogContext &, const QString &)
{
}

static QString make_doc(const QString &which)
{
    pki_type typ = typeMap[which];
    int match = which.endsWith("-clp") ? F_CLIPBOARD : 0;
    QString doc;
    for (const pki_export *exp : pki_export::select(typ, 0)) {
        if (exp->match_all(match)) {
            doc += QString("  - **%1:** (\\*.%2) %3\n").arg(exp->desc).arg(exp->extension).arg(exp->help);
        }
    }
    return doc;
}

int main(int argc, char *argv[])
{
	qInstallMessageHandler(noop);

	if (argc < 2) {
		qWarning() << "Need type argument: <x509|key|req|revocation|template>";
		return EXIT_FAILURE;
	}
	pki_export::init_elements();
    if (!typeMap.contains(argv[1])) {
        qWarning() << QString("Unknown type: %1").arg(argv[1]);
        return EXIT_FAILURE;
    }
    QByteArray doc = make_doc(argv[1]).toUtf8();
	if (argc > 2) {
		QFile f(argv[2]);
		f.open(QIODevice::WriteOnly);
		f.write(doc);
		f.close();
	} else {
		QTextStream out(stdout);
		out << doc;
	}
	pki_export::free_elements();
	return EXIT_SUCCESS;
}
