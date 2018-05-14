TEMPLATE = app
TARGET = secrets-tool

CONFIG += link_pkgconfig console
PKGCONFIG += Qt5Core Qt5DBus
packagesExist(qt5-boostable) {
    PKGCONFIG += qt5-boostable
}

#PKGCONFIG += sailfishsecrets sailfishcrypto
include($$PWD/../../lib/libsailfishsecrets.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)

SOURCES += $$PWD/commandhelper.cpp $$PWD/main.cpp
HEADERS += $$PWD/commandhelper.h
OTHER_FILES += $$PWD/manual-test.sh $$PWD/manual-test-devicelock.sh

target.path = /usr/bin
INSTALLS += target
