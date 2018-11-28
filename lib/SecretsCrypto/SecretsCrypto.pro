TEMPLATE = lib
TARGET = sailfishsecretscrypto
TARGET = $$qtLibraryTarget($$TARGET)
target.path = /usr/lib

CONFIG -= qt
CONFIG += create_pc create_pc create_prl no_install_prl link_pkgconfig
CONFIG += debug
PKGCONFIG += glib-2.0 gio-2.0

PUBLIC_HEADERS += \
    $$PWD/sf-secrets-manager.h \
    $$PWD/sf-secrets-collection.h \
    $$PWD/sf-secrets-invocation-request.h \
    $$PWD/sf-secrets-secret.h \
    $$PWD/sf-secrets.h \
    \
    $$PWD/sf-crypto.h \
    $$PWD/sf-crypto-manager.h \
    $$PWD/sf-crypto-key.h



HEADERS += $$PUBLIC_HEADERS \
    $$PWD/sf-secrets-manager-private.h

SOURCES += \
    $$PWD/sf-secrets-manager.c \
    $$PWD/sf-secrets-collection.c \
    $$PWD/sf-secrets-interaction-request.c \
    $$PWD/sf-secrets-secret.c \
    \
    $$PWD/sf-crypto-manager.c \
    $$PWD/sf-crypto-key.c


develheaders.path = /usr/include/Sailfish/SecretsCrypto/
develheaders.files = $$PUBLIC_HEADERS

pkgconfig.files = $$TARGET.pc
pkgconfig.path = $$target.path/pkgconfig

QMAKE_PKGCONFIG_NAME = lib$$TARGET
QMAKE_PKGCONFIG_LIBDIR = $$target.path
QMAKE_PKGCONFIG_INCDIR = $$develheaders.path
QMAKE_PKGCONFIG_VERSION = $$VERSION
QMAKE_PKGCONFIG_DESCRIPTION = Sailfish OS Secrets And Crypto C API
QMAKE_PKGCONFIG_DESTDIR = pkgconfig
QMAKE_PKGCONFIG_REQUIRES = gio-2.0

INSTALLS += target pkgconfig develheaders

DBUS_INTERFACES = \
	sf-secrets-interaction.xml

gdbus_header.output = ${QMAKE_FILE_BASE}.h
gdbus_header.variable_out = HEADERS
gdbus_header.commands = gdbus-codegen --c-namespace SfSecrets --interface-prefix org.sailfishos.secrets --header --output ${QMAKE_FILE_OUT} ${QMAKE_FILE_NAME}
gdbus_header.input = DBUS_INTERFACES

gdbus_source.output = ${QMAKE_FILE_BASE}.c
gdbus_source.variable_out = SOURCES
gdbus_source.commands = gdbus-codegen --c-namespace SfSecrets --interface-prefix org.sailfishos.secrets --body --output ${QMAKE_FILE_OUT} ${QMAKE_FILE_NAME}; sed -i "'0,/^\o43\s*ifdef\s\s*G_OS_UNIX/s/^\o43\s*ifdef\s\s*G_OS_UNIX/\o43undef G_OS_UNIX\n&/'" ${QMAKE_FILE_OUT}
gdbus_source.depends = ${QMAKE_FILE_BASE}.h
gdbus_source.input = DBUS_INTERFACES

QMAKE_EXTRA_COMPILERS += gdbus_header gdbus_source
