TEMPLATE = app
TARGET = sailfishcryptoexample
TARGETPATH = /usr/bin
target.path = $$TARGETPATH

CONFIG += qt
QT += core dbus
QMAKE_CXXFLAGS += -fPIE
CONFIG += link_pkgconfig

# normally would do:
#PKGCONFIG += sailfishsecrets sailfishcrypto
# but here we use .pri's to include/depend etc.
include($$PWD/../../../lib/libsailfishsecrets.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)

PKGCONFIG += Qt5Core Qt5DBus
packagesExist(qt5-boostable) {
    PKGCONFIG += qt5-boostable
}

HEADERS += helper.h
SOURCES += main.cpp
OTHER_FILES += README
INSTALLS += target
