TEMPLATE = lib
CONFIG+=plugin
TARGET=qsqlcipher
TARGET = $$qtLibraryTarget($$TARGET)

QT += sql sql-private

CONFIG += link_pkgconfig
PKGCONFIG += sqlcipher

HEADERS += \
    $$PWD/qt-private/qsql_sqlite_p.h

SOURCES += \
    $$PWD/qt-private/qsql_sqlite.cpp \
    $$PWD/smain.cpp

OTHER_FILES += \
    $$PWD/sqlcipher.json \
    $$PWD/qt-private/README \
    $$PWD/LICENSE.LGPLv21 \
    $$PWD/README.md

target.path=/usr/lib/qt5/plugins/sqldrivers
INSTALLS += target
