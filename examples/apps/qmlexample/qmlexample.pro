TEMPLATE = app
TARGET = sailfishcryptoqmlexample
TARGETPATH = /usr/bin
target.path = $$TARGETPATH

CONFIG += qt
QT += core dbus gui qml quick
QMAKE_CXXFLAGS += -fPIE
CONFIG += link_pkgconfig

# normally would do:
#PKGCONFIG += sailfishsecrets sailfishcrypto
# but here we use .pri's to include/depend etc.
include($$PWD/../../../lib/libsailfishsecrets.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)

PKGCONFIG += Qt5Core Qt5DBus Qt5Qml Qt5Quick
packagesExist(qdeclarative5-boostable) {
    PKGCONFIG += qdeclarative5-boostable
}

SOURCES += main.cpp
OTHER_FILES += main.qml README
RESOURCES += resources.qrc
INSTALLS += target
