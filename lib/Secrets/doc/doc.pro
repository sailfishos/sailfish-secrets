TEMPLATE = aux

CONFIG += mer-qdoc-template
MER_QDOC.project = sailfish-secrets
MER_QDOC.config = sailfish-secrets.qdocconf
MER_QDOC.style = offline
MER_QDOC.path = /usr/share/doc/Sailfish/Secrets/

OTHER_FILES += \
    $$PWD/sailfish-secrets.qdocconf \
    $$PWD/sailfish-secrets-overview.qdoc \
    $$PWD/sailfish-secrets-plugins.qdoc \
    $$PWD/sailfish-secrets.cpp \
    $$PWD/../../../doc/index.qdoc \
    $$PWD/../../../doc/sailfish.cpp
