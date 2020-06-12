TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishsecrets-testpasswordagentauth
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += nemodevicelock

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN
HEADERS += $$PWD/../../../plugins/passwordagentauthplugin/passwordagentplugin.h
SOURCES += $$PWD/../../../plugins/passwordagentauthplugin/passwordagentplugin.cpp

target.path=$$[QT_INSTALL_LIBS]/Sailfish/Secrets/
INSTALLS += target
