#include "sf-crypto.h"

G_DEFINE_QUARK(SfCryptoError, sf_crypto_error)

G_DEFINE_BOXED_TYPE(SfCryptoPluginInfo, sf_crypto_plugin_info, sf_crypto_plugin_info_copy, sf_crypto_plugin_info_free)

void sf_crypto_plugin_info_free(SfCryptoPluginInfo *info)
{
    if (G_UNLIKELY(!info))
        return;

    g_free(info->display_name);
    g_free(info->name);

    g_free(info);
}

SfCryptoPluginInfo *sf_crypto_plugin_info_copy(const SfCryptoPluginInfo *other)
{
    SfCryptoPluginInfo *rv;

    if (G_UNLIKELY(!other))
        return NULL;

    rv = g_new0(SfCryptoPluginInfo, 1);

    rv->display_name = g_strdup(other->display_name);
    rv->name = g_strdup(other->name);
    rv->version = other->version;
    rv->state = other->state;

    return rv;
}


