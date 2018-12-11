#ifndef SF_CRYPTO_KEY_PRIVATE_H
#define SF_CRYPTO_KEY_PRIVATE_H

#include "sf-crypto-key.h"

#define SF_CRYPTO_KEY_VARIANT_STRING "((sss)iiiiiayayayaaya{sv})"

GVariant *_sf_crypto_key_to_variant(SfCryptoKey *key);
SfCryptoKey *_sf_crypto_key_from_variant(GVariant *variant);

#endif /* SF_CRYPTO_KEY_PRIVATE_H */
