TEMPLATE = app
TARGET = authentication-client

include($$PWD/../../../lib/libsailfishsecrets.pri)

DEFINES += TEST_AUTHENTICATION_LIBRARY=\"\\\"$$[QT_INSTALL_LIBS]/Sailfish/Secrets/libsailfishsecrets-testpasswordagentauth.so\\\"\"

CONFIG += link_pkgconfig
PKGCONFIG += qt5-boostable

SOURCES += main.cpp

SOURCES += $$PWD/../../../lib/Secrets/Plugins/extensionplugins.cpp
HEADERS += $$PWD/../../../lib/Secrets/Plugins/extensionplugins.h

target.path = /opt/tests/Sailfish/Secrets/

INSTALLS += target
