#ifndef SF_CRYPTO_MANAGER_PRIVATE_H
#define SF_CRYPTO_MANAGER_PRIVATE_H

GDBusProxy *_sf_crypto_manager_get_dbus_proxy(SfCryptoManager *manager);
void _sf_crypto_manager_result_bytearray_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data);
void _sf_crypto_manager_result_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data);
GVariant *_sf_crypto_manager_dbus_call_finish(GObject *source_object,
        GAsyncResult *res,
        GError **error,
        GVariantIter *iter);

#endif /* SF_CRYPTO_MANAGER_PRIVATE_H */
