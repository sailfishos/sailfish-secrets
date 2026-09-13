TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishsecrets-deviceauth
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += nemodevicelock
include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecretspluginapi.pri)
HEADERS += plugin.h
SOURCES += plugin.cpp
target.path = $$[QT_INSTALL_LIBS]/Sailfish/Secrets/
INSTALLS += target
