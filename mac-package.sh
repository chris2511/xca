#!/bin/sh

VERSION=$(cat VERSION)
echo "Creating distribution disk image for xca $VERSION"

QTDEPLOY=misc/deployqt

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
    echo "curl http://e42.us/binaries/deployqt.bz2 |bzcat - >misc/deployqt && chmod +x misc/deployqt"
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
if [ -x "$QTDEPLOY" ]
    echo "Warning: this release package will require users to have installed Qt on their systems."
    then $QTDEPLOY $DMGSTAGELOC/xca.app
fi

cp COPYRIGHT dmgstage

if [ -e "doc/xca.html" ]
then
    mkdir $DMGSTAGELOC/manual
    # copy the manual onto the disk image so that users can read it without launching the app
    cp doc/xc*.html $DMGSTAGELOC/manual
    # also copy the manual into the bundle so that help works
    cp doc/xc*.html $DMGSTAGELOC/xca.app/Contents/Resources
else
    echo "Warning: No manual will be included on the disk image and help will be unavailable."
fi

hdiutil create -srcfolder $DMGSTAGELOC xca-$VERSION.dmg

