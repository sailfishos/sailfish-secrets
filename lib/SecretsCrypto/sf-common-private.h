#ifndef SF_COMMON_PRIVATE_H
#define SF_COMMON_PRIVATE_H

#include <glib.h>

#define EMPTY_IF_NULL(s) ((s) ? (s) : "")

GVariant *_sf_variant_new_variant_map_string_or_empty(GHashTable *hash_table);
GVariant *_sf_variant_new_bytes_or_empty(GBytes *bytes);
GVariant *_sf_variant_new_variant_map_or_empty(GHashTable *hash_table);

GBytes *_sf_bytes_new_from_variant_or_null(GVariant *variant);
GBytes *_sf_bytes_new_from_variant(GVariant *variant);
GHashTable *_sf_hash_table_new_string_from_variant(GVariant *variant);

#endif /* SF_COMMON_PRIVATE_H */
