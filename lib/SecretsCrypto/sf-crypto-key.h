#ifndef SF_CRYPTO_KEY_H
#define SF_CRYPTO_KEY_H

#include <glib-object.h>

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
		const gchar *plugin_name);
SfCryptoKey *sf_crypto_key_new_public(GBytes *public_key);
SfCryptoKey *sf_crypto_key_new_private(GBytes *private_key);
SfCryptoKey *sf_crypto_key_new_secret(GBytes *secret_key);

const gchar *sf_crypto_key_get_identifier(SfCryptoKey *secret);

void sf_crypto_key_set_filter_field(SfCryptoKey *secret, const gchar *key, const gchar *value);
const gchar *sf_crypto_key_get_filter_field(SfCryptoKey *secret, const gchar *key);

void sf_crypto_key_take_custom_param(SfCryptoKey *key, GBytes *custom_param);
void sf_crypto_key_add_custom_param(SfCryptoKey *key, GBytes *custom_param);
void sf_crypto_key_add_custom_param_data(SfCryptoKey *key, gconstpointer data, size_t data_size);

#endif /* SF_CRYPTO_KEY_H */
