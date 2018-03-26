INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH

HEADERS += \
    $$PWD/crypto_p.h \
    $$PWD/cryptorequestprocessor_p.h \
    $$PWD/cryptopluginfunctionwrappers_p.h

SOURCES += \
    $$PWD/crypto.cpp \
    $$PWD/cryptorequestprocessor.cpp \
    $$PWD/cryptopluginfunctionwrappers.cpp

