#ifndef CRYPTOEXAMPLE_HELPER_H
#define CRYPTOEXAMPLE_HELPER_H

#include <QtCore/QObject>
#include <QtCore/QByteArray>

#include <Secrets/secretmanager.h>
#include <Secrets/secret.h>

#include <Crypto/cryptomanager.h>
#include <Crypto/key.h>

class Helper : public QObject
{
    Q_OBJECT

public:
    enum Operation {
        Encrypt,
        Decrypt
    };

    enum Mode {
        NormalMode,
        TestMode
    };

    Helper(Operation operation = Encrypt, Mode mode = NormalMode, QObject *parent = Q_NULLPTR);
    virtual ~Helper() Q_DECL_OVERRIDE;

    int exitCode() const;

public Q_SLOTS:
    void getLicenseCode();
    void storeLicenseCode(const QByteArray &licenseCode);
    void createKey(const QByteArray &licenseCode);
    void encryptData(const Sailfish::Crypto::Key &key);
    void decryptData(const Sailfish::Crypto::Key &key);

Q_SIGNALS:
    void finished();

private:
    Sailfish::Secrets::SecretManager m_secretManager;
    Sailfish::Crypto::CryptoManager m_cryptoManager;

    Sailfish::Secrets::Secret::Identifier m_licenseCodeIdent;

    bool m_encryptOperation;
    bool m_testMode;

    int m_exitCode;
};

#endif // CRYPTOEXAMPLE_HELPER_H
