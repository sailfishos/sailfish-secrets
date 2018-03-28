TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishsecrets-testsqlcipher
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += libcrypto

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)
include($$PWD/../../../database/database.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN

INCLUDEPATH += \
    $$PWD/../../../plugins/sqlcipherplugin \
    $$PWD/../../../plugins/opensslcryptoplugin \
    $$PWD/../../../plugins/opensslcryptoplugin/evp
DEPENDPATH += \
    $$PWD/../../../plugins/sqlcipherplugin \
    $$PWD/../../../plugins/opensslcryptoplugin \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/

HEADERS += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_p.h \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_helpers_p.h \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.h \
    $$PWD/../../../plugins/sqlcipherplugin/sqlcipherplugin.h

SOURCES += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp.cpp \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.cpp \
    $$PWD/../../../plugins/sqlcipherplugin/sqlcipherplugin.cpp \
    $$PWD/../../../plugins/sqlcipherplugin/encryptedstorageplugin.cpp \
    $$PWD/../../../plugins/sqlcipherplugin/cryptoplugin.cpp

OTHER_FILES += \
    $$PWD/../../plugins/opensslcryptoplugin/cryptoplugin_common.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
