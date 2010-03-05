#!/bin/sh

VERSION=$(cat VERSION)
echo "Creating distribution disk image for xca $VERSION"

QTDEPLOY=misc/macdeployqt

if [ -x "`which deployqt`" ]
then
    QTDEPLOY=`which deployqt`
fi

if [ -x "$QTDEPLOY" ]
then
    echo "$QTDEPLOY will be used for packaging qt into release builds of the application bundle"
else
    echo "No copy of qtdeploy could be found. qtdeploy is highly recommended for building release versions of xca intended for redistribution."
    echo "The command"
    echo "curl http://git.hohnstaedt.de/macdeployqt.bz2 |bzcat - >misc/macdeployqt && chmod +x misc/macdeployqt"
    echo "will fetch a pre-built copy. Otherwise, download and build from here: "
    echo "http://labs.trolltech.com/blogs/2007/08/23/deploying-mac-applications-without-the-hassle/"
fi

if [ ! -d "build/Release/xca.app" ]
then
    echo "No release build was found. This script only makes sense for packaging release builds."
    exit
fi
DMGSTAGELOC=dmgstage/xca
rm -rf $DMGSTAGELOC
mkdir -p $DMGSTAGELOC
if ! cp -r build/Release/xca.app $DMGSTAGELOC
then
    echo "Could not copy the release build into directory dmgstage."
    exit
fi
if [ -x "$QTDEPLOY" ]; then
     $QTDEPLOY $DMGSTAGELOC/xca.app /Developer/Applications/Qt/plugins
else
    echo "Warning: this release package will require users to have installed Qt on their systems."
fi

cp COPYRIGHT $DMGSTAGELOC/COPYRIGHT.txt
ln -s /Applications $DMGSTAGELOC

if [ -z "$HTML_DOCDIR" -a -e "doc/xca.html" ]
then
    HTML_DOCDIR="doc"
fi

if [ -n "$HTML_DOCDIR" ]
then
    echo "Using HTML documentation from: $HTML_DOCDIR"
    mkdir $DMGSTAGELOC/manual
    # copy the manual onto the disk image so that users can read it
    # without launching the app
    cp $HTML_DOCDIR/xc*.html $DMGSTAGELOC/manual
    # also copy the manual into the bundle so that help works
    cp $HTML_DOCDIR/xc*.html $DMGSTAGELOC/xca.app/Contents/Resources
else
    echo "Warning: No manual will be included on the disk image and help will be unavailable. (Set HTML_DOCDIR to the directory containing xca.html ff.)"
fi

hdiutil create -srcfolder $DMGSTAGELOC xca-$VERSION.dmg

