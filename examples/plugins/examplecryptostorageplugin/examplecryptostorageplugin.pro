TEMPLATE = lib
CONFIG += qt plugin hide_symbols link_pkgconfig c++11
TARGET = sailfishsecrets-examplecryptostorageplugin
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += sailfishcryptopluginapi

HEADERS += \
    $$PWD/plugin.h

SOURCES += \
    $$PWD/plugin.cpp \
    $$PWD/encryptedstorageplugin.cpp \
    $$PWD/cryptoplugin.cpp

OTHER_FILES += $$PWD/rpm/examplecryptostorageplugin.spec

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
