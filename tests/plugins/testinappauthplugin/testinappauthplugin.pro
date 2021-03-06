TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-testinappauth
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN
HEADERS += $$PWD/../../../plugins/inappauthplugin/plugin.h
SOURCES += $$PWD/../../../plugins/inappauthplugin/plugin.cpp

target.path=$$[QT_INSTALL_LIBS]/Sailfish/Secrets/
INSTALLS += target
