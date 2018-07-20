TEMPLATE = aux

MANUAL_TESTS += \
    $$PWD/customlock-accessrelock-keys.sh \
    $$PWD/customlock-accessrelock-secrets.sh \
    $$PWD/customlock-keepunlocked-keys.sh \
    $$PWD/customlock-keepunlocked-secrets.sh \
    $$PWD/devicelock-devicelockrelock-keys.sh \
    $$PWD/devicelock-devicelockrelock-secrets.sh \
    $$PWD/devicelock-keepunlocked-keys.sh \
    $$PWD/devicelock-keepunlocked-secrets.sh \
    $$PWD/collection-ownership.sh \
    $$PWD/standalone-secrets.sh

MATRIX_TESTS += \
    $$PWD/matrix/run-matrix-tests.sh \
    $$PWD/matrix/001.sh \
    $$PWD/matrix/002.sh \
    $$PWD/matrix/003.sh \
    $$PWD/matrix/004.sh \
    $$PWD/matrix/005.sh \
    $$PWD/matrix/006.sh \
    $$PWD/matrix/007.sh \
    $$PWD/matrix/008.sh \
    $$PWD/matrix/009.a.sh \
    $$PWD/matrix/009.b.sh \
    $$PWD/matrix/009.c.sh \
    $$PWD/matrix/010.a.sh \
    $$PWD/matrix/010.b.sh \
    $$PWD/matrix/010.c.sh \
    $$PWD/matrix/011.a.sh \
    $$PWD/matrix/011.b.sh \
    $$PWD/matrix/011.c.sh \
    $$PWD/matrix/012.a.sh \
    $$PWD/matrix/012.b.sh \
    $$PWD/matrix/012.c.sh \
    $$PWD/matrix/015.a.sh \
    $$PWD/matrix/015.b.sh \
    $$PWD/matrix/015.c.sh

OTHER_FILES += \
    $$MANUAL_TESTS \
    $$MATRIX_TESTS \
    $$PWD/matrix/README

matrixtests.path=/opt/tests/Sailfish/Crypto/matrix/
matrixtests.files=$$MATRIX_TESTS
INSTALLS += matrixtests
