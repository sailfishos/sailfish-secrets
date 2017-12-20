TEMPLATE = lib
TARGET = sailfishsecretscrypto
TARGET = $$qtLibraryTarget($$TARGET)
target.path = /usr/lib

CONFIG -= qt
CONFIG += create_pc create_pc create_prl no_install_prl link_pkgconfig
PKGCONFIG += glib-2.0 gio-2.0 gio-unix-2.0

PUBLIC_HEADERS += \
    $$PWD/secrets.h \
    $$PWD/crypto.h

HEADERS += $$PUBLIC_HEADERS

SOURCES += \
    $$PWD/secrets.c \
    $$PWD/crypto.c

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
