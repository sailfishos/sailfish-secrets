#ifndef SF_CRYPTO_CIPHER_SESSION_H
#define SF_CRYPTO_CIPHER_SESSION_H

#include <glib-object.h>
#include <gio/gio.h>
#include "sf-crypto-manager.h"
#include "sf-crypto.h"
#include "sf-crypto-key.h"

#define SF_TYPE_CRYPTO_CIPHER_SESSION (sf_crypto_cipher_session_get_type())
#define SF_CRYPTO_CIPHER_SESSION(o) (G_TYPE_CHECK_INSTANCE_CAST((o), SF_TYPE_CRYPTO_CIPHER_SESSION, SfCryptoCipherSession))
#define SF_IS_CRYPTO_CIPHER_SESSION(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), SF_TYPE_CRYPTO_CIPHER_SESSION))

typedef struct SfCryptoCipherSession_ SfCryptoCipherSession;
typedef struct SfCryptoCipherSessionClass_ SfCryptoCipherSessionClass;

struct SfCryptoCipherSession_ {
    GObject parent;
};

struct SfCryptoCipherSessionClass_ {
    GObjectClass parent_class;
};

GType sf_crypto_cipher_session_get_type(void);

void sf_crypto_cipher_session_new(SfCryptoManager *manager,
        GBytes *iv,
        SfCryptoKey *key,
        SfCryptoOperation operation,
        SfCryptoBlockMode block_mode,
        SfCryptoEncryptionPadding padding,
        SfCryptoSignaturePadding signature_padding,
        SfCryptoDigest digest,
        GHashTable *custom_parameters,
        const gchar *provider_name,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data);
SfCryptoCipherSession *sf_crypto_cipher_session_new_finish(GAsyncResult *res, GError **error);

void sf_crypto_cipher_session_update_authentication(SfCryptoCipherSession *session,
        GBytes *authentication_data,
        GHashTable *custom_parameters,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data);
gboolean sf_crypto_cipher_session_update_authentication_finish(GAsyncResult *res, GError **error);

void sf_crypto_cipher_session_update(SfCryptoCipherSession *session,
        GBytes *data,
        GHashTable *custom_parameters,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data);
gboolean sf_crypto_cipher_session_update_finish(GAsyncResult *res,
        GBytes **data,
        GError **error);

void sf_crypto_cipher_session_close(SfCryptoCipherSession *session,
        GBytes *data,
        GHashTable *custom_parameters,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data);
gboolean sf_crypto_cipher_session_close_finish(GAsyncResult *res,
        GBytes **data,
        SfCryptoVerificationStatus *verification_status,
        GError **error);

#endif /* SF_CRYPTO_CIPHER_SESSION_H */
