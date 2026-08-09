/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "../../../plugins/keymintcryptoplugin/keymintbinderclient.cpp"

#include <QtTest/QtTest>

class tst_keymintbinderclient : public QObject
{
    Q_OBJECT

private slots:
    void capabilityPayloadIsStrict();
    void authSetRoundTripAndPolicy();
    void authenticationIdentityPolicy();
    void opaqueKeyAndEnvelopeRoundTrip();
    void hardwareAuthTokenParsing();
    void attestationFailsClosed();
};

void tst_keymintbinderclient::capabilityPayloadIsStrict()
{
    const qint32 supportedLevels[] = {
        SecurityLevelSoftware,
        SecurityLevelTrustedEnvironment,
        SecurityLevelStrongBox
    };
    for (qint32 securityLevel : supportedLevels) {
        const QByteArray response = serializeCapabilitiesResponse(securityLevel);
        QCOMPARE(response.size(), 8);
        Cursor cursor(response);
        quint32 version = 0;
        quint32 parsedSecurityLevel = 100;
        QVERIFY(cursor.take(&version));
        QVERIFY(cursor.take(&parsedSecurityLevel));
        QVERIFY(cursor.atEnd());
        QCOMPARE(version, ProtocolVersion);
        QCOMPARE(parsedSecurityLevel, quint32(securityLevel));
    }

    QVERIFY(serializeCapabilitiesResponse(-1).isEmpty());
    QVERIFY(serializeCapabilitiesResponse(100).isEmpty());
}

void tst_keymintbinderclient::authSetRoundTripAndPolicy()
{
    const quint64 secureUserId = 0x123456789abcdef0ULL;
    QVector<Parameter> parameters;
    parameters << scalarParameter(TagUserSecureId, secureUserId)
               << scalarParameter(TagUserAuthType, AuthenticatorPassword)
               << scalarParameter(TagAuthTimeout, 30)
               << blobParameter(TagAssociatedData, QByteArray("aad"));

    const QByteArray serialized = serializeAuthSet(parameters);
    QVERIFY(!serialized.isEmpty());

    QVector<Parameter> parsed;
    QVERIFY(parseAuthSet(serialized, &parsed));
    QCOMPARE(parsed.size(), parameters.size());
    QCOMPARE(parsed.at(0).tag, TagUserSecureId);
    QCOMPARE(parsed.at(0).valueTag, qint32(ValueLongInteger));
    QCOMPARE(parsed.at(0).scalar, secureUserId);
    QCOMPARE(parsed.at(3).tag, TagAssociatedData);
    QCOMPARE(parsed.at(3).valueTag, qint32(ValueBlob));
    QCOMPARE(parsed.at(3).blob, QByteArray("aad"));

    QVERIFY(policyMatchesIdentity(parsed, secureUserId, 0));
    QVERIFY(!policyMatchesIdentity(parsed, secureUserId + 1, 0));

    QVector<Parameter> noAuthentication;
    noAuthentication << scalarParameter(TagNoAuthRequired, 1);
    QVERIFY(policyMatchesIdentity(noAuthentication, secureUserId + 1, 0));

    QByteArray truncated = serialized;
    truncated.chop(1);
    QVERIFY(!parseAuthSet(truncated, &parsed));

    QByteArray wrongType = serialized;
    const quint32 type = qToLittleEndian(quint32(2));
    wrongType.replace(12, sizeof(type),
                      reinterpret_cast<const char *>(&type), sizeof(type));
    QVERIFY(!parseAuthSet(wrongType, &parsed));

    QByteArray trailing = serialized;
    trailing.append('\0');
    QVERIFY(!parseAuthSet(trailing, &parsed));
}

void tst_keymintbinderclient::authenticationIdentityPolicy()
{
    const quint64 secureUserId = Q_UINT64_C(0x1020304050607080);
    const quint64 fingerprintAuthenticatorId
            = Q_UINT64_C(0x2122232425262728);

    QVector<Parameter> biometric;
    biometric << scalarParameter(TagUserSecureId,
                                 fingerprintAuthenticatorId)
              << scalarParameter(TagUserAuthType,
                                 AuthenticatorFingerprint);
    QVERIFY(policyMatchesIdentity(biometric, secureUserId,
                                  fingerprintAuthenticatorId));
    QVERIFY(!policyMatchesIdentity(biometric, secureUserId,
                                   fingerprintAuthenticatorId + 1));

    QVector<Parameter> wrongType = biometric;
    wrongType[1] = scalarParameter(TagUserAuthType, AuthenticatorPassword);
    QVERIFY(!policyMatchesIdentity(wrongType, secureUserId,
                                   fingerprintAuthenticatorId));

    QVector<Parameter> mixed = biometric;
    mixed << scalarParameter(TagUserSecureId,
                             fingerprintAuthenticatorId + 1);
    QVERIFY(!policyMatchesIdentity(mixed, secureUserId,
                                   fingerprintAuthenticatorId));

    QVector<Parameter> rootFingerprint;
    rootFingerprint << scalarParameter(TagUserSecureId, secureUserId)
                    << scalarParameter(TagUserAuthType,
                                       AuthenticatorFingerprint);
    QVERIFY(policyMatchesIdentity(rootFingerprint, secureUserId,
                                  fingerprintAuthenticatorId));

    HardwareAuthToken token;
    token.present = true;
    token.userId = secureUserId;
    token.authenticatorType = AuthenticatorPassword;
    QVERIFY(tokenMatchesIdentity(token, secureUserId,
                                 fingerprintAuthenticatorId));
    token.authenticatorId = fingerprintAuthenticatorId;
    QVERIFY(!tokenMatchesIdentity(token, secureUserId,
                                  fingerprintAuthenticatorId));

    token.authenticatorType = AuthenticatorFingerprint;
    QVERIFY(tokenMatchesIdentity(token, secureUserId,
                                 fingerprintAuthenticatorId));
    QVERIFY(!tokenMatchesIdentity(token, secureUserId,
                                  fingerprintAuthenticatorId + 1));
    ++token.userId;
    QVERIFY(!tokenMatchesIdentity(token, secureUserId,
                                  fingerprintAuthenticatorId));
}

void tst_keymintbinderclient::opaqueKeyAndEnvelopeRoundTrip()
{
    OpaqueKey key;
    key.rawBlob = QByteArray::fromHex("010203040506");
    key.certificates << QByteArray("certificate-one")
                     << QByteArray("certificate-two");
    key.publicKey = QByteArray("public-key");

    const QByteArray serializedKey = serializeOpaqueKey(key);
    QVERIFY(!serializedKey.isEmpty());

    OpaqueKey parsedKey;
    QVERIFY(parseOpaqueKey(serializedKey, &parsedKey));
    QCOMPARE(parsedKey.rawBlob, key.rawBlob);
    QCOMPARE(parsedKey.certificates, key.certificates);
    QCOMPARE(parsedKey.publicKey, key.publicKey);

    QByteArray trailingKey = serializedKey;
    trailingKey.append('\0');
    QVERIFY(!parseOpaqueKey(trailingKey, &parsedKey));

    OpaqueKey legacyKey;
    QVERIFY(parseOpaqueKey(QByteArray("legacy-keymint-blob"), &legacyKey));
    QCOMPARE(legacyKey.rawBlob, QByteArray("legacy-keymint-blob"));

    KeyMintEnvelope envelope;
    envelope.sailfishUserId = 100000;
    envelope.secureUserId = 0x1122334455667788ULL;
    envelope.identityEpoch = QByteArray(IdentityEpochSize, '\x42');
    envelope.backendVersion = BackendVersion;
    envelope.keyBlob = serializedKey;
    envelope.nonce = QByteArray(GcmNonceSize, '\x24');
    envelope.ciphertext = QByteArray(RootKeySize, '\x55');
    envelope.authenticationTag = QByteArray(GcmTagSize, '\x66');

    const QByteArray serializedEnvelope = serializeEnvelope(envelope);
    QVERIFY(!serializedEnvelope.isEmpty());

    KeyMintEnvelope parsedEnvelope;
    QVERIFY(parseEnvelope(serializedEnvelope, &parsedEnvelope));
    QCOMPARE(parsedEnvelope.sailfishUserId, envelope.sailfishUserId);
    QCOMPARE(parsedEnvelope.secureUserId, envelope.secureUserId);
    QCOMPARE(parsedEnvelope.identityEpoch, envelope.identityEpoch);
    QCOMPARE(parsedEnvelope.backendVersion, envelope.backendVersion);
    QCOMPARE(parsedEnvelope.keyBlob, envelope.keyBlob);
    QCOMPARE(parsedEnvelope.nonce, envelope.nonce);
    QCOMPARE(parsedEnvelope.ciphertext, envelope.ciphertext);
    QCOMPARE(parsedEnvelope.authenticationTag, envelope.authenticationTag);
    QCOMPARE(authenticatedEnvelopeData(parsedEnvelope),
             authenticatedEnvelopeData(envelope));

    QByteArray trailingEnvelope = serializedEnvelope;
    trailingEnvelope.append('\0');
    QVERIFY(!parseEnvelope(trailingEnvelope, &parsedEnvelope));

    QByteArray wrongMagic = serializedEnvelope;
    wrongMagic[0] = 'X';
    QVERIFY(!parseEnvelope(wrongMagic, &parsedEnvelope));
}

void tst_keymintbinderclient::hardwareAuthTokenParsing()
{
    const quint64 challenge = 0x0102030405060708ULL;
    const quint64 secureUserId = 0x1112131415161718ULL;
    const quint64 authenticatorId = 0x2122232425262728ULL;
    const quint64 timestamp = 0x3132333435363738ULL;
    QByteArray mac(32, '\0');
    mac[31] = '\x7f';

    QByteArray masterToken;
    appendLittleEndian(&masterToken, quint32(1));
    appendLittleEndian(&masterToken, challenge);
    appendLittleEndian(&masterToken, secureUserId);
    appendLittleEndian(&masterToken, authenticatorId);
    appendLittleEndian(&masterToken, quint32(AuthenticatorPassword));
    appendLittleEndian(&masterToken, timestamp);
    masterToken.append(mac);

    HardwareAuthToken parsedMaster;
    QVERIFY(parseMasterHardwareAuthToken(masterToken, &parsedMaster));
    QVERIFY(parsedMaster.present);
    QCOMPARE(parsedMaster.challenge, challenge);
    QCOMPARE(parsedMaster.userId, secureUserId);
    QCOMPARE(parsedMaster.timestamp, timestamp);
    QCOMPARE(parsedMaster.mac, mac);

    QByteArray zeroMacMaster = masterToken;
    zeroMacMaster.replace(zeroMacMaster.size() - 32, 32, QByteArray(32, '\0'));
    QVERIFY(parseMasterHardwareAuthToken(zeroMacMaster, &parsedMaster));
    QCOMPARE(parsedMaster.mac, QByteArray(32, '\0'));

    QByteArray zeroTimestampMaster = masterToken;
    const quint64 zero = 0;
    zeroTimestampMaster.replace(32, sizeof(zero),
                                reinterpret_cast<const char *>(&zero), sizeof(zero));
    QVERIFY(!parseMasterHardwareAuthToken(zeroTimestampMaster, &parsedMaster));

    QByteArray appToken;
    appendLittleEndian(&appToken, quint32(1));
    appendLittleEndian(&appToken, quint32(1));
    appendLittleEndian(&appToken, challenge);
    appendLittleEndian(&appToken, secureUserId);
    appendLittleEndian(&appToken, authenticatorId);
    appendLittleEndian(&appToken, quint32(2));
    appendLittleEndian(&appToken, timestamp);
    appendBlob(&appToken, mac);

    Cursor cursor(appToken);
    HardwareAuthToken parsedApp;
    QVERIFY(parseAppHardwareAuthToken(&cursor, &parsedApp));
    QVERIFY(cursor.atEnd());
    QVERIFY(parsedApp.present);
    QCOMPARE(parsedApp.authenticatorType, quint32(2));
    QCOMPARE(parsedApp.mac, mac);

    QByteArray zeroMacApp = appToken;
    zeroMacApp.replace(zeroMacApp.size() - 32, 32, QByteArray(32, '\0'));
    Cursor zeroMacCursor(zeroMacApp);
    QVERIFY(parseAppHardwareAuthToken(&zeroMacCursor, &parsedApp));
    QVERIFY(zeroMacCursor.atEnd());
    QCOMPARE(parsedApp.mac, QByteArray(32, '\0'));

    QByteArray absentToken;
    appendLittleEndian(&absentToken, quint32(0));
    Cursor absentCursor(absentToken);
    QVERIFY(parseAppHardwareAuthToken(&absentCursor, &parsedApp));
    QVERIFY(absentCursor.atEnd());
    QVERIFY(!parsedApp.present);

    QVERIFY(emptyVerificationToken(QByteArray()));
    QVERIFY(!emptyVerificationToken(QByteArray("malformed")));

    QByteArray verificationToken;
    appendLittleEndian(&verificationToken, quint32(1));
    appendLittleEndian(&verificationToken, quint64(0));
    appendLittleEndian(&verificationToken, quint64(0));
    appendLittleEndian(&verificationToken, quint32(0));
    appendBlob(&verificationToken,
               serializeAuthSet(QVector<Parameter>()));
    appendBlob(&verificationToken, QByteArray());
    QVERIFY(emptyVerificationToken(verificationToken));

    QByteArray hardwareVerificationToken = verificationToken;
    const quint32 hardwareSecurityLevel = qToLittleEndian(quint32(1));
    hardwareVerificationToken.replace(
                sizeof(quint32) + 2 * sizeof(quint64),
                sizeof(hardwareSecurityLevel),
                reinterpret_cast<const char *>(&hardwareSecurityLevel),
                sizeof(hardwareSecurityLevel));
    QVERIFY(!emptyVerificationToken(hardwareVerificationToken));
}

void tst_keymintbinderclient::attestationFailsClosed()
{
    KeyMintBinderClient client;
    QByteArray response("stale-certificate-chain");
    const KeyMintBinderClient::CallResult result = client.oneShot(
                AttestOperation, QByteArray("request-is-not-forwarded"), &response);
    QVERIFY(result.transportSucceeded);
    QCOMPARE(result.keyMintError, qint32(KmUnimplemented));
    QVERIFY(!result.succeeded());
    QVERIFY(response.isEmpty());
}

QTEST_APPLESS_MAIN(tst_keymintbinderclient)

#include "tst_keymintbinderclient.moc"
