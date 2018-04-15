/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "util_p.h"

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Util::transformSecretsResult(
        const Sailfish::Secrets::Result &result)
{
    Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
    if (result.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        if (result.errorCode() == Sailfish::Secrets::Result::InvalidSecretError
                || result.errorCode() == Sailfish::Secrets::Result::InvalidSecretIdentifierError
                || result.errorCode() == Sailfish::Secrets::Result::InvalidCollectionError
                || result.errorCode() == Sailfish::Secrets::Result::InvalidExtensionPluginError) {
            retn.setErrorCode(Sailfish::Crypto::Result::InvalidKeyIdentifier);
        } else {
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        }
        retn.setStorageErrorCode(static_cast<int>(result.errorCode()));
        retn.setErrorMessage(result.errorMessage());
    } else if (result.code() == Sailfish::Secrets::Result::Pending) {
        retn.setCode(Sailfish::Crypto::Result::Pending);
    }
    return retn;
}
