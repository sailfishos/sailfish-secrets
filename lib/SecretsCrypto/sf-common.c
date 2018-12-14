#include "sf-common-private.h"

GVariant *_sf_variant_new_bytes_or_empty(GBytes *bytes)
{
    if (!bytes)
        return g_variant_new_array(G_VARIANT_TYPE_BYTE, NULL, 0);
    return g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
            g_bytes_get_data(bytes, NULL),
            g_bytes_get_size(bytes) / sizeof(guchar),
            sizeof(guchar));
}

GBytes *_sf_bytes_new_from_variant_or_null(GVariant *variant)
{
    gconstpointer data;
    gsize n_elements;

    data = g_variant_get_fixed_array(variant, &n_elements, sizeof(guchar));
    if (n_elements == 0)
        return NULL;
    return g_bytes_new(data, n_elements * sizeof(guchar));
}

GVariant *_sf_variant_new_variant_map_string_or_empty(GHashTable *hash_table)
{
    GVariantDict var_dict;

    g_variant_dict_init(&var_dict, NULL);

    if (hash_table) {
        GHashTableIter ht_iter;
        gpointer key;
        gpointer value;
        g_hash_table_iter_init(&ht_iter, hash_table);
        while (g_hash_table_iter_next(&ht_iter, &key, &value))
            g_variant_dict_insert_value(&var_dict, key, g_variant_new_string(value));
    }

    return g_variant_dict_end(&var_dict);
}

GHashTable *_sf_hash_table_new_string_from_variant(GVariant *variant)
{
    GHashTable *res;
    GVariantIter iter;
    GVariant *item;
    gchar *key;

    g_variant_iter_init(&iter, variant);

    if (!g_variant_iter_next(&iter, "{sv}", &key, &item))
        return NULL;

    res = g_hash_table_new_full(g_str_hash, g_str_equal,
            g_free, g_free);

    do {
        g_hash_table_replace(res, key, g_variant_dup_string(item, NULL));
        g_variant_unref(item);
    } while (g_variant_iter_next(&iter, "{sv}", &key, &item));

    return res;
}
