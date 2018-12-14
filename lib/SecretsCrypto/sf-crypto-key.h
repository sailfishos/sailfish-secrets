#ifndef SF_CRYPTO_KEY_H
#define SF_CRYPTO_KEY_H

#include <glib-object.h>
#include "sf-crypto.h"

#define SF_TYPE_CRYPTO_KEY (sf_crypto_key_get_type())
#define SF_CRYPTO_KEY(o) (G_TYPE_CHECK_INSTANCE_CAST((o), SF_TYPE_CRYPTO_KEY, SfCryptoKey))
#define SF_IS_CRYPTO_KEY(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), SF_TYPE_CRYPTO_KEY))

typedef enum SfCryptoKeyOrigin_ {
    SF_CRYPTO_KEY_ORIGIN_UNKNOWN       = 0,
    SF_CRYPTO_KEY_ORIGIN_IMPORTED,
    SF_CRYPTO_KEY_ORIGIN_DEVICE,
    SF_CRYPTO_KEY_ORIGIN_SECURE_DEVICE
} SfCryptoKeyOrigin;

typedef enum SfCryptoKeyConstraint_ {
    SF_CRYPTO_KEY_CONSTRAINT_NO_DATA          = 0,
    SF_CRYPTO_KEY_CONSTRAINT_META_DATA        = 1,
    SF_CRYPTO_KEY_CONSTRAINT_PUBLIC_KEY_DATA   = 2,
    SF_CRYPTO_KEY_CONSTRAINT_PRIVATE_KEY_DATA  = 4,
    SF_CRYPTO_KEY_CONSTRAINT_SECRET_KEY_DATA   = SF_CRYPTO_KEY_CONSTRAINT_PRIVATE_KEY_DATA
} SfCryptoKeyConstraint;

typedef struct SfCryptoKey_ SfCryptoKey;
typedef struct SfCryptoKeyClass_ SfCryptoKeyClass;

struct SfCryptoKey_ {
    GInitiallyUnowned parent;
};

struct SfCryptoKeyClass_ {
    GInitiallyUnownedClass parent_class;
};

GType sf_crypto_key_get_type(void);
SfCryptoKey *sf_crypto_key_new(void);
SfCryptoKey *sf_crypto_key_new_reference(const gchar *name,
        const gchar *collection_name,
        const gchar *plugin_name);
SfCryptoKey *sf_crypto_key_new_template(const gchar *name,
        const gchar *collection_name,
        const gchar *plugin_name,
        SfCryptoAlgorithm algorithm,
        gint key_size);
SfCryptoKey *sf_crypto_key_new_public(SfCryptoAlgorithm algorithm,
        gint key_size,
        GBytes *public_key);
SfCryptoKey *sf_crypto_key_new_private(SfCryptoAlgorithm algorithm,
        gint key_size,
        GBytes *private_key);
SfCryptoKey *sf_crypto_key_new_secret(SfCryptoAlgorithm algorithm, GBytes *secret_key);

const gchar *sf_crypto_key_get_name(SfCryptoKey *key);
void sf_crypto_key_set_name(SfCryptoKey *key, const gchar *name);
const gchar *sf_crypto_key_get_collection_name(SfCryptoKey *key);
void sf_crypto_key_set_collection_name(SfCryptoKey *key, const gchar *collection_name);
const gchar *sf_crypto_key_get_plugin_name(SfCryptoKey *key);
void sf_crypto_key_set_plugin_name(SfCryptoKey *key, const gchar *plugin_name);
SfCryptoKeyOrigin sf_crypto_key_get_origin(SfCryptoKey *key);
void sf_crypto_key_set_origin(SfCryptoKey *key, SfCryptoKeyOrigin origin);
SfCryptoAlgorithm sf_crypto_key_get_algorithm(SfCryptoKey *key);
void sf_crypto_key_set_algorithm(SfCryptoKey *key, SfCryptoAlgorithm algorithm);
SfCryptoOperation sf_crypto_key_get_operations(SfCryptoKey *key);
void sf_crypto_key_set_operations(SfCryptoKey *key, SfCryptoOperation operations);
SfCryptoKeyConstraint sf_crypto_key_get_constraints(SfCryptoKey *key);
void sf_crypto_key_set_constraints(SfCryptoKey *key, SfCryptoKeyConstraint constraints);
int sf_crypto_key_get_key_size(SfCryptoKey *key);
void sf_crypto_key_set_key_size(SfCryptoKey *key, int key_size);
GBytes *sf_crypto_key_get_public_key(SfCryptoKey *key);
void sf_crypto_key_set_public_key(SfCryptoKey *key, GBytes *public_key);
GBytes *sf_crypto_key_get_private_key(SfCryptoKey *key);
void sf_crypto_key_set_private_key(SfCryptoKey *key, GBytes *private_key);
GBytes *sf_crypto_key_get_secret_key(SfCryptoKey *key);
void sf_crypto_key_set_secret_key(SfCryptoKey *key, GBytes *secret_key);
GPtrArray *sf_crypto_key_get_custom_params(SfCryptoKey *key);
void sf_crypto_key_set_custom_params(SfCryptoKey *key, GPtrArray *custom_params);
GHashTable *sf_crypto_key_get_filter_data(SfCryptoKey *key);
void sf_crypto_key_set_filter_data(SfCryptoKey *key, GHashTable *filter_data);
void sf_crypto_key_set_filter_field(SfCryptoKey *secret, const gchar *key, const gchar *value);
const gchar *sf_crypto_key_get_filter_field(SfCryptoKey *secret, const gchar *key);

void sf_crypto_key_take_custom_param(SfCryptoKey *key, GBytes *custom_param);
void sf_crypto_key_add_custom_param(SfCryptoKey *key, GBytes *custom_param);
void sf_crypto_key_add_custom_param_data(SfCryptoKey *key, gconstpointer data, size_t data_size);

#endif /* SF_CRYPTO_KEY_H */
