#include <QTextStream>
#include <QDebug>
#include <QByteArray>
#include <QFile>

#include "arguments.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		qWarning() << "Need type argument: <man|rst|completion>";
		return EXIT_FAILURE;
	}
	QByteArray doc = arguments::doc(argv[1]).toUtf8();
	if (doc.isEmpty()) {
		qWarning() << QString("Doc was empty: %1").arg(argv[1]);
		return EXIT_FAILURE;
	}
	if (argc > 2) {
		QFile f(argv[2]);
		f.open(QIODevice::WriteOnly);
		f.write(doc);
		f.close();
	} else {
		QTextStream out(stdout);
		out << doc;
	}
	return EXIT_SUCCESS;
}
