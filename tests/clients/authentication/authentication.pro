TEMPLATE = app
TARGET = authentication-client

include($$PWD/../../../lib/libsailfishsecrets.pri)

CONFIG += link_pkgconfig
PKGCONFIG += qt5-boostable

SOURCES += main.cpp

SOURCES += $$PWD/../../../lib/SecretsPluginApi/extensionplugins.cpp
HEADERS += $$PWD/../../../lib/SecretsPluginApi/extensionplugins.h

target.path = /opt/tests/Sailfish/Secrets/

INSTALLS += target
