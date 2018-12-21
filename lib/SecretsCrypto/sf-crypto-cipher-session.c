#include "sf-crypto-cipher-session.h"
#include "sf-crypto-manager-private.h"
#include "sf-crypto-key-private.h"
#include "sf-common-private.h"

enum SfCryptoCipherSessionProperties {
    PROP_MANAGER = 1,
    PROP_IV,
    PROP_KEY,
    PROP_OPERATION,
    PROP_BLOCK_MODE,
    PROP_PADDING,
    PROP_SIGNATURE_PADDING,
    PROP_DIGEST,
    PROP_CUSTOM_PARAMETERS,
    PROP_CRYPTO_PROVIDER
};

struct SfCryptoCipherSessionPrivate_
{
    SfCryptoManager *manager;
    guint32 session_id;
    GBytes *iv;
    SfCryptoKey *key;
    SfCryptoOperation operation;
    SfCryptoBlockMode block_mode;
    SfCryptoEncryptionPadding padding;
    SfCryptoSignaturePadding signature_padding;
    SfCryptoDigest digest;
    GHashTable *custom_params;
    gchar *crypto_provider;
};

typedef struct SfCryptoCipherSessionPrivate_ SfCryptoCipherSessionPrivate;

static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface);

G_DEFINE_TYPE_WITH_CODE(SfCryptoCipherSession, sf_crypto_cipher_session, G_TYPE_OBJECT,
        G_ADD_PRIVATE(SfCryptoCipherSession)
        G_IMPLEMENT_INTERFACE(G_TYPE_ASYNC_INITABLE, _async_initable_iface_init))

static void _sf_crypto_cipher_session_initialize_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    SfCryptoCipherSession *session = SF_CRYPTO_CIPHER_SESSION(g_task_get_source_object(task));
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    GError *error = NULL;
    GVariantIter iter;
    GVariant *ret = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_variant_iter_next(&iter, "u", &priv->session_id);

    g_variant_unref(ret);
    g_task_return_boolean(task, TRUE);
    g_object_unref(task);
}

static void _async_initable_init_async (GAsyncInitable *initable,
        gint io_priority,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    GTask *task = g_task_new(initable, cancellable, callback, user_data);
    SfCryptoCipherSession *session = SF_CRYPTO_CIPHER_SESSION(initable);
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    GDBusProxy *proxy = _sf_crypto_manager_get_dbus_proxy(priv->manager);

    g_task_set_priority(task, io_priority);

    g_dbus_proxy_call(proxy,
            "initializeCipherSession",
            g_variant_new("(@ay"
                "@" SF_CRYPTO_KEY_VARIANT_STRING
                "(i)(i)(i)(i)(i)"
                "@a{sv}s)",
                _sf_variant_new_bytes_or_empty(priv->iv),
                _sf_crypto_key_to_variant(priv->key),
                priv->operation, priv->block_mode,
                priv->padding, priv->signature_padding,
                priv->digest,
                _sf_variant_new_variant_map_or_empty(priv->custom_params),
                priv->crypto_provider),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_crypto_cipher_session_initialize_ready,
            task);
    g_object_unref(proxy);

    if (priv->key) {
        g_object_unref(priv->key);
        priv->key = NULL;
    }
    if (priv->iv) {
        g_bytes_unref(priv->iv);
        priv->iv = NULL;
    }
    if (priv->custom_params) {
        g_hash_table_unref(priv->custom_params);
        priv->custom_params = NULL;
    }
}

static gboolean _async_initable_init_finish (GAsyncInitable *initable,
        GAsyncResult *res,
        GError **error)
{
    (void)initable;
    return g_task_propagate_boolean(G_TASK(res), error);
}


static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
    async_initable_iface->init_async = _async_initable_init_async;
    async_initable_iface->init_finish = _async_initable_init_finish;
}

static void _sf_crypto_cipher_session_get_property(GObject *object,
    guint property_id,
    GValue *value,
    GParamSpec *pspec)
{
    SfCryptoCipherSession *session = SF_CRYPTO_CIPHER_SESSION(object);
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);

    (void)pspec;

    switch (property_id) {
    case PROP_MANAGER:
        g_value_set_object(value, priv->manager);
        break;

    case PROP_OPERATION:
        g_value_set_int(value, priv->operation);
        break;

    case PROP_BLOCK_MODE:
        g_value_set_int(value, priv->block_mode);
        break;

    case PROP_PADDING:
        g_value_set_int(value, priv->padding);
        break;

    case PROP_SIGNATURE_PADDING:
        g_value_set_int(value, priv->signature_padding);
        break;

    case PROP_DIGEST:
        g_value_set_int(value, priv->digest);
        break;

    case PROP_CRYPTO_PROVIDER:
        g_value_set_string(value, priv->crypto_provider);
        break;

    default:
        break;
    }
}

static void _sf_crypto_cipher_session_set_property(GObject *object,
    guint property_id,
    const GValue *value,
    GParamSpec *pspec)
{
    SfCryptoCipherSession *session = SF_CRYPTO_CIPHER_SESSION(object);
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);

    (void)pspec;

    switch (property_id) {
    case PROP_MANAGER:
        if (priv->manager)
            g_object_unref(priv->manager);
        priv->manager = g_value_dup_object(value);
        break;

    case PROP_IV:
        if (priv->iv)
            g_bytes_unref(priv->iv);
        priv->iv = g_value_dup_boxed(value);
        break;

    case PROP_KEY:
        if (priv->key)
            g_object_unref(priv->key);
        priv->key = g_value_get_object(value);
        if (priv->key)
            g_object_ref_sink(priv->key);
        break;

    case PROP_OPERATION:
        priv->operation = g_value_get_int(value);
        break;

    case PROP_BLOCK_MODE:
        priv->block_mode = g_value_get_int(value);
        break;

    case PROP_PADDING:
        priv->padding = g_value_get_int(value);
        break;

    case PROP_SIGNATURE_PADDING:
        priv->signature_padding = g_value_get_int(value);
        break;

    case PROP_DIGEST:
        priv->digest = g_value_get_int(value);
        break;

    case PROP_CUSTOM_PARAMETERS:
        if (priv->custom_params)
            g_hash_table_unref(priv->custom_params);
        priv->custom_params = g_value_dup_boxed(value);
        break;

    case PROP_CRYPTO_PROVIDER:
        if (priv->crypto_provider)
            g_free(priv->crypto_provider);
        priv->crypto_provider = g_value_dup_string(value);
        break;

    default:
        break;
    }
}

static void _sf_crypto_cipher_session_finalize(GObject *object)
{
    SfCryptoCipherSession *session = SF_CRYPTO_CIPHER_SESSION(object);
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);

    if (priv->key)
        g_object_unref(priv->key);
    if (priv->iv)
        g_bytes_unref(priv->iv);
    if (priv->custom_params)
        g_hash_table_unref(priv->custom_params);
    if (priv->crypto_provider)
        g_free(priv->crypto_provider);
    if (priv->manager)
        g_object_unref(priv->manager);
}

static void sf_crypto_cipher_session_init(SfCryptoCipherSession *session)
{
    (void)session;
}

static void sf_crypto_cipher_session_class_init(SfCryptoCipherSessionClass *session_class)
{
    G_OBJECT_CLASS(session_class)->finalize = _sf_crypto_cipher_session_finalize;
    G_OBJECT_CLASS(session_class)->set_property = _sf_crypto_cipher_session_set_property;
    G_OBJECT_CLASS(session_class)->get_property = _sf_crypto_cipher_session_get_property;

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_MANAGER,
            g_param_spec_object("manager",
                "manager",
                "SfCryptoManager instance",
                SF_TYPE_CRYPTO_MANAGER,
                G_PARAM_READWRITE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_IV,
            g_param_spec_boxed("initialization-vector",
                "initialization-vector",
                "Initialization vector",
                G_TYPE_BYTES,
                G_PARAM_WRITABLE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_KEY,
            g_param_spec_object("key",
                "key",
                "SfCryptoKey instance",
                SF_TYPE_CRYPTO_KEY,
                G_PARAM_WRITABLE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_OPERATION,
            g_param_spec_int("operation",
                "operation",
                "Crypto operation",
                SF_CRYPTO_OPERATION_UNKNOWN,
                (SF_CRYPTO_OPERATION_DERIVE_KEY << 1) - 1,
                SF_CRYPTO_OPERATION_UNKNOWN,
                G_PARAM_READWRITE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_BLOCK_MODE,
            g_param_spec_int("block-mode",
                "block-mode",
                "Crypto block mode",
                SF_CRYPTO_BLOCK_MODE_UNKNOWN,
                SF_CRYPTO_BLOCK_MODE_LAST,
                SF_CRYPTO_BLOCK_MODE_UNKNOWN,
                G_PARAM_READWRITE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_PADDING,
            g_param_spec_int("padding",
                "padding",
                "Crypto encryption padding",
                SF_CRYPTO_ENCRYPTION_PADDING_UNKNOWN,
                SF_CRYPTO_ENCRYPTION_PADDING_LAST,
                SF_CRYPTO_ENCRYPTION_PADDING_UNKNOWN,
                G_PARAM_READWRITE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_SIGNATURE_PADDING,
            g_param_spec_int("signature-padding",
                "signature-padding",
                "Crypto signature padding",
                SF_CRYPTO_SIGNATURE_PADDING_UNKNOWN,
                SF_CRYPTO_SIGNATURE_PADDING_LAST,
                SF_CRYPTO_SIGNATURE_PADDING_UNKNOWN,
                G_PARAM_READWRITE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_DIGEST,
            g_param_spec_int("digest",
                "digest",
                "Crypto digest",
                SF_CRYPTO_DIGEST_UNKNOWN,
                SF_CRYPTO_DIGEST_FUNCTION_LAST,
                SF_CRYPTO_DIGEST_UNKNOWN,
                G_PARAM_READWRITE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_CUSTOM_PARAMETERS,
            g_param_spec_boxed("custom-parameters",
                "custom-parameters",
                "Custom parameters",
                G_TYPE_HASH_TABLE,
                G_PARAM_WRITABLE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(session_class),
            PROP_CRYPTO_PROVIDER,
            g_param_spec_string("crypto-provider",
                "crypto-provider",
                "Cryptographic provider",
                NULL,
                G_PARAM_READWRITE |
                G_PARAM_CONSTRUCT_ONLY |
                G_PARAM_STATIC_STRINGS));
}

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
        gpointer user_data)
{
    g_async_initable_new_async(SF_TYPE_CRYPTO_CIPHER_SESSION,
            G_PRIORITY_DEFAULT,
            cancellable,
            callback,
            user_data,
            "manager", manager,
            "initialization-vector", iv,
            "key", key,
            "operation", operation,
            "block-mode", block_mode,
            "padding", padding,
            "signature-padding", signature_padding,
            "digest", digest,
            "custom-parameters", custom_parameters,
            "crypto-provider", provider_name,
            NULL);
}

SfCryptoCipherSession *sf_crypto_cipher_session_new_finish(GAsyncResult *res, GError **error)
{
    GObject *src_obj = g_async_result_get_source_object(res);
    GObject *obj = g_async_initable_new_finish(G_ASYNC_INITABLE(src_obj),
            res, error);
    g_object_unref(src_obj);

    return SF_CRYPTO_CIPHER_SESSION(obj);
}

static void _sf_crypto_cipher_session_update_authentication_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    _sf_crypto_manager_result_ready(source_object, res, user_data);
}

void sf_crypto_cipher_session_update_authentication(SfCryptoCipherSession *session,
        GBytes *authentication_data,
        GHashTable *custom_parameters,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    GTask *task = g_task_new(session, cancellable, callback, user_data);
    GDBusProxy *proxy = _sf_crypto_manager_get_dbus_proxy(priv->manager);

    g_dbus_proxy_call(proxy,
            "updateCipherSessionAuthentication",
            g_variant_new("(@ay"
                "@a{sv}su)",
                _sf_variant_new_bytes_or_empty(authentication_data),
                _sf_variant_new_variant_map_or_empty(custom_parameters),
                priv->crypto_provider,
                priv->session_id),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_crypto_cipher_session_update_authentication_ready,
            task);
    g_object_unref(proxy);
}

gboolean sf_crypto_cipher_session_update_authentication_finish(GAsyncResult *res, GError **error)
{
    return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_crypto_cipher_session_update_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GVariantIter iter;
    GVariant *ret = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);
    GVariant *var;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    var = g_variant_iter_next_value(&iter);
    g_variant_unref(ret);
    g_task_return_pointer(task, _sf_bytes_new_from_variant_or_null(var), (GDestroyNotify)g_bytes_unref);
    g_variant_unref(var);
    g_object_unref(task);
}

void sf_crypto_cipher_session_update(SfCryptoCipherSession *session,
        GBytes *data,
        GHashTable *custom_parameters,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    GTask *task = g_task_new(session, cancellable, callback, user_data);
    GDBusProxy *proxy = _sf_crypto_manager_get_dbus_proxy(priv->manager);

    g_dbus_proxy_call(proxy,
            "updateCipherSession",
            g_variant_new("(@ay"
                "@a{sv}su)",
                _sf_variant_new_bytes_or_empty(data),
                _sf_variant_new_variant_map_or_empty(custom_parameters),
                priv->crypto_provider,
                priv->session_id),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_crypto_cipher_session_update_ready,
            task);
    g_object_unref(proxy);
}

gboolean sf_crypto_cipher_session_update_finish(GAsyncResult *res,
        GBytes **data,
        GError **error)
{
    GError *err = NULL;
    GBytes *tmp;

    tmp = g_task_propagate_pointer(G_TASK(res), &err);

    if (error)
        *error = err;
    else if (err)
        g_error_free(err);

    if (data)
        *data = tmp;
    else if (tmp) {
        g_warning("Ignoring returned data from cipher session");
        g_bytes_unref(tmp);
    }

    return !err;
}

static void _sf_crypto_cipher_session_finalize_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GVariantIter iter;
    GVariant *ret = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);
    GVariant *var;
    gint32 verification_status;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    var = g_variant_iter_next_value(&iter);
    g_variant_iter_next(&iter, "(i)", &verification_status);
    g_task_set_task_data(task, GINT_TO_POINTER(verification_status), NULL);

    g_variant_unref(ret);
    g_task_return_pointer(task, _sf_bytes_new_from_variant_or_null(var), (GDestroyNotify)g_bytes_unref);
    g_variant_unref(var);
    g_object_unref(task);
}

void sf_crypto_cipher_session_close(SfCryptoCipherSession *session,
        GBytes *data,
        GHashTable *custom_params,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    GTask *task = g_task_new(session, cancellable, callback, user_data);
    GDBusProxy *proxy = _sf_crypto_manager_get_dbus_proxy(priv->manager);

    g_dbus_proxy_call(proxy,
            "finalizeCipherSession",
            g_variant_new("(@ay"
                "@a{sv}su)",
                _sf_variant_new_bytes_or_empty(data),
                _sf_variant_new_variant_map_or_empty(custom_params),
                priv->crypto_provider,
                priv->session_id),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_crypto_cipher_session_finalize_ready,
            task);
    g_object_unref(proxy);
}

gboolean sf_crypto_cipher_session_close_finish(GAsyncResult *res,
        GBytes **data,
        SfCryptoVerificationStatus *verification_status,
        GError **error)
{
    GError *err = NULL;
    GBytes *tmp;

    if (verification_status)
        *verification_status = GPOINTER_TO_INT(g_task_get_task_data(G_TASK(res)));
    tmp = g_task_propagate_pointer(G_TASK(res), &err);

    if (error)
        *error = err;
    else if (err)
        g_error_free(err);

    if (data)
        *data = tmp;
    else if (tmp) {
        g_warning("Ignoring returned data from cipher session");
        g_bytes_unref(tmp);
    }

    return !err;
}


SfCryptoManager *sf_crypto_cipher_session_get_manager(SfCryptoCipherSession *session)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    return priv->manager;
}

SfCryptoOperation sf_crypto_cipher_session_get_operation(SfCryptoCipherSession *session)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    return priv->operation;
}

SfCryptoBlockMode sf_crypto_cipher_session_get_block_mode(SfCryptoCipherSession *session)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    return priv->block_mode;
}

SfCryptoEncryptionPadding sf_crypto_cipher_session_get_padding(SfCryptoCipherSession *session)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    return priv->padding;
}

SfCryptoSignaturePadding sf_crypto_cipher_session_get_signature_padding(SfCryptoCipherSession *session)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    return priv->signature_padding;
}

SfCryptoDigest sf_crypto_cipher_session_get_digest(SfCryptoCipherSession *session)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    return priv->digest;
}

const gchar *sf_crypto_cipher_session_get_crypto_provider(SfCryptoCipherSession *session)
{
    SfCryptoCipherSessionPrivate *priv = sf_crypto_cipher_session_get_instance_private(session);
    return priv->crypto_provider;
}
