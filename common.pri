unix|macx {
    QMAKE_CXXFLAGS += -Werror
}

QT -= gui
CONFIG += rtti_off
CONFIG += c++11

# Ignore errors about errors RSA_new and friends for now.
# Has to be ported to not directly use openssl data types but their wrapper API's
# May break in future OpenSSL releases
QMAKE_CXXFLAGS+= -Wno-error=deprecated-declarations
