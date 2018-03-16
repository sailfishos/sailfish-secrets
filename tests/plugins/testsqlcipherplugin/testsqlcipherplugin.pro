TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-testsqlcipher
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)
include($$PWD/../../../database/database.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN

INCLUDEPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp/
DEPENDPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp/

HEADERS += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_p.h \
    $$PWD/../../../plugins/sqlcipherplugin/sqlcipherplugin.h

SOURCES += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp.c \
    $$PWD/../../../plugins/sqlcipherplugin/sqlcipherplugin.cpp \
    $$PWD/../../../plugins/sqlcipherplugin/encryptedstorageplugin.cpp \
    $$PWD/../../../plugins/sqlcipherplugin/cryptoplugin.cpp

OTHER_FILES += \
    $$PWD/../../plugins/opensslcryptoplugin/cryptoplugin_common.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
