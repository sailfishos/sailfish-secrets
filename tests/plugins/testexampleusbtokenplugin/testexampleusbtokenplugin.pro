TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishsecrets-testexampleusbtoken
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += libcrypto

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)
include($$PWD/../../../database/database.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN

INCLUDEPATH += \
    $$PWD/../../../plugins/exampleusbtokenplugin \
    $$PWD/../../../plugins/opensslcryptoplugin \
    $$PWD/../../../plugins/opensslcryptoplugin/evp
DEPENDPATH += \
    $$PWD/../../../plugins/exampleusbtokenplugin \
    $$PWD/../../../plugins/opensslcryptoplugin \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/

HEADERS += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_p.h \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_helpers_p.h \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.h \
    $$PWD/../../../plugins/exampleusbtokenplugin/exampleusbtokenplugin.h

SOURCES += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp.cpp \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.cpp \
    $$PWD/../../../plugins/exampleusbtokenplugin/exampleusbtokenplugin.cpp \
    $$PWD/../../../plugins/exampleusbtokenplugin/encryptedstorageplugin.cpp \
    $$PWD/../../../plugins/exampleusbtokenplugin/cryptoplugin.cpp

OTHER_FILES += \
    $$PWD/../../plugins/opensslcryptoplugin/cryptoplugin_common.cpp

target.path=$$[QT_INSTALL_LIBS]/Sailfish/Secrets/
INSTALLS += target
