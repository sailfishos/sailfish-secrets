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
    $$PWD/matrix/013.a.sh \
    $$PWD/matrix/013.b.sh \
    $$PWD/matrix/013.c.sh \
    $$PWD/matrix/014.a.sh \
    $$PWD/matrix/014.b.sh \
    $$PWD/matrix/014.c.sh \
    $$PWD/matrix/015.a.sh \
    $$PWD/matrix/015.b.sh \
    $$PWD/matrix/015.c.sh \
    $$PWD/matrix/025.a.sh \
    $$PWD/matrix/025.b.sh \
    $$PWD/matrix/025.c.sh \
    $$PWD/matrix/026.a.sh \
    $$PWD/matrix/026.b.sh \
    $$PWD/matrix/026.c.sh \
    $$PWD/matrix/027.a.sh \
    $$PWD/matrix/027.b.sh \
    $$PWD/matrix/027.c.sh \
    $$PWD/matrix/028.a.sh \
    $$PWD/matrix/028.b.sh \
    $$PWD/matrix/028.c.sh \
    $$PWD/matrix/029.a.sh \
    $$PWD/matrix/029.b.sh \
    $$PWD/matrix/029.c.sh \
    $$PWD/matrix/030.a.sh \
    $$PWD/matrix/030.b.sh \
    $$PWD/matrix/030.c.sh \
    $$PWD/matrix/031.a.sh \
    $$PWD/matrix/031.b.sh \
    $$PWD/matrix/031.c.sh \
    $$PWD/matrix/032.a.sh \
    $$PWD/matrix/032.b.sh \
    $$PWD/matrix/032.c.sh \
    $$PWD/matrix/033.a.sh \
    $$PWD/matrix/033.b.sh \
    $$PWD/matrix/033.c.sh \
    $$PWD/matrix/034.a.sh \
    $$PWD/matrix/034.b.sh \
    $$PWD/matrix/034.c.sh \
    $$PWD/matrix/035.a.sh \
    $$PWD/matrix/035.b.sh \
    $$PWD/matrix/035.c.sh \
    $$PWD/matrix/036.a.sh \
    $$PWD/matrix/036.b.sh \
    $$PWD/matrix/036.c.sh \
    $$PWD/matrix/037.a.sh \
    $$PWD/matrix/037.b.sh \
    $$PWD/matrix/037.c.sh \
    $$PWD/matrix/038.a.sh \
    $$PWD/matrix/038.b.sh \
    $$PWD/matrix/038.c.sh \
    $$PWD/matrix/039.a.sh \
    $$PWD/matrix/039.b.sh \
    $$PWD/matrix/039.c.sh

OTHER_FILES += \
    $$MANUAL_TESTS \
    $$MATRIX_TESTS \
    $$PWD/matrix/README

matrixtests.path=/opt/tests/Sailfish/Crypto/matrix/
matrixtests.files=$$MATRIX_TESTS
INSTALLS += matrixtests
