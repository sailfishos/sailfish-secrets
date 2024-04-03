unix|macx {
    QMAKE_CXXFLAGS += -Werror
}

QT -= gui
CONFIG += rtti_off
CONFIG += c++11

# Ignore errors about errors RSA_new and friends for now.
# Has to be ported to not directly use openssl data types but their wrapper API's
# May break in future OpenSSL releases

# QVariant::operator<` has been deprecated in Qt 5.15 however without
# providing a replacement until Qt 6 with `QVariant::compare()`.
# FIXME: Qt6
# Related:
# https://www.mail-archive.com/development@qt-project.org/msg39450.html

QMAKE_CXXFLAGS+= -Wno-error=deprecated-declarations
