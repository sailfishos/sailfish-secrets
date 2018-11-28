#ifndef SF_CRYPTO_KEY_PRIVATE_H
#define SF_CRYPTO_KEY_PRIVATE_H

#include "sf-crypto-key.h"

#define SF_CRYPTO_KEY_VARIANT_STRING "((sss)iiiiiayayayaaya{sv})"

GVariant *_sf_crypto_key_to_variant(SfCryptoKey *key);
SfCryptoKey *_sf_crypto_key_from_variant(GVariant *variant);

GVariant *_sf_variant_new_variant_map_or_empty(GHashTable *hash_table);
GVariant *_sf_variant_new_bytes_or_empty(GBytes *bytes);

GBytes *_sf_bytes_new_from_variant_or_null(GVariant *variant);

#endif /* SF_CRYPTO_KEY_PRIVATE_H */
