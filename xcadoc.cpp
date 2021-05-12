#include <iostream>
#include <QString>
#include <QFile>

#include "arguments.h"

using namespace std;

int main(int argc, char *argv[])
{
	if (argc < 2) {
		cerr << "Need type argument: <man|rst|completion>" << endl;
		return EXIT_FAILURE;
	}

	QString doc = arguments::doc(argv[1]);
	if (doc.isEmpty()) {
		cerr << "Doc was empty: " << argv[1] << endl;
		return EXIT_FAILURE;
	}
	if (argc == 2) {
		cout << doc.toUtf8().constData() << endl;
		return EXIT_SUCCESS;
	}
	QFile f(argv[2]);
	f.open(QIODevice::WriteOnly);
	f.write(doc.toUtf8());
	f.close();
	return EXIT_SUCCESS;
}
