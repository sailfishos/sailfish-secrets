#include "sf-secrets.h"
#include "sf-secrets-manager.h"
#include "sf-secrets-manager-private.h"
#include "sf-secrets-interaction.h"
#include "sf-secrets-interaction-request.h"
#include "sf-secrets-interaction-request-private.h"
#include "sf-common-private.h"

typedef struct SfSecretsManagerPrivate_ SfSecretsManagerPrivate;
typedef enum SfSecretsManagerSignal_ {
    SIGNAL_NEW_INTERACTION_REQUEST,
    SIGNAL_COUNT
} SfSecretsManagerSignal;

static guint _sf_secrets_manager_signals[SIGNAL_COUNT];

struct SfSecretsManagerPrivate_
{
    GDBusProxy *proxy;
    gchar *application_id;
    gboolean user_interaction_mode_set;
    SfSecretsUserInteractionMode user_interaction_mode;

    SfSecretsInteraction *interaction_interface;
    gchar *interaction_service_address;
    GDBusServer *server;
    GHashTable *connections;
    GHashTable *requests;
};

static void _async_initable_iface_init(GAsyncInitableIface *async_initable_iface);
static void _async_initable_init_async(GAsyncInitable *initable,
        gint io_priority,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data);
static gboolean _async_initable_init_finish(GAsyncInitable *initable,
        GAsyncResult *res,
        GError **error);

enum SfSecretManagerProperties {
    PROP_APPLICATION_ID = 1,
    PROP_USER_INTERACTION_MODE,
};

G_DEFINE_TYPE_WITH_CODE(SfSecretsManager, sf_secrets_manager, G_TYPE_OBJECT,
        G_ADD_PRIVATE(SfSecretsManager)
        G_IMPLEMENT_INTERFACE(G_TYPE_ASYNC_INITABLE, _async_initable_iface_init))

static void sf_secrets_manager_init(SfSecretsManager *manager)
{
    (void)manager;
}

static gboolean _sf_secrets_manager_ptr_equal(gpointer key, gpointer value, gpointer user_data)
{
    (void)key;
    return value == user_data;
}

static void _sf_secrets_manager_remove_request(SfSecretsManager *manager,
        SfSecretsInteractionRequest *gone_request)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

    g_hash_table_foreach_remove(priv->requests, _sf_secrets_manager_ptr_equal, gone_request);
}

static void _sf_secrets_manager_finalize(GObject *object)
{
    SfSecretsManager *manager = SF_SECRETS_MANAGER(object);
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

    if (priv->proxy)
        g_object_unref(priv->proxy);

    if (priv->server)
        g_object_unref(priv->server);

    if (priv->requests) {
        GHashTableIter i;
        gpointer id;
        gpointer request;
        g_hash_table_iter_init(&i, priv->requests);
        while (g_hash_table_iter_next(&i, &id, &request))
            g_object_weak_unref(G_OBJECT(request), (GWeakNotify)_sf_secrets_manager_remove_request, manager);
        g_hash_table_unref(priv->requests);
    }

    if (priv->connections)
        g_hash_table_unref(priv->connections);

    if (priv->interaction_service_address)
        g_free(priv->interaction_service_address);

    if (priv->interaction_interface)
        g_object_unref(priv->interaction_interface);

    if (priv->application_id)
        g_free(priv->application_id);
}

static void _sf_secrets_manager_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *spec)
{
    SfSecretsManager *manager = SF_SECRETS_MANAGER(object);
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

    (void)spec;

    switch (property_id) {
        case PROP_APPLICATION_ID:
            g_value_set_string(value, priv->application_id);
            break;
        case PROP_USER_INTERACTION_MODE:
            g_value_set_uint(value, priv->user_interaction_mode);
            break;
        default:
            g_warning("Unknown property %u", property_id);
            break;
    }
}

static void _sf_secrets_manager_interaction_connection_closed(SfSecretsManager *manager,
        gboolean remote_peer_vanished,
        GError *error,
        GDBusConnection *connection)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

    (void)remote_peer_vanished;
    (void)error;

    g_hash_table_remove(priv->connections, connection);
}

static gboolean _sf_secrets_manager_new_interaction_connection(SfSecretsManager *manager,
        GDBusConnection *connection,
        GDBusServer *server)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

    (void)server;

    g_hash_table_insert(priv->connections, g_object_ref(connection), connection);

    g_signal_connect_object(connection,
            "closed",
            G_CALLBACK(_sf_secrets_manager_interaction_connection_closed),
            manager,
            G_CONNECT_SWAPPED);

    g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(priv->interaction_interface),
            connection,
            "/",
            NULL);

    return TRUE;
}

static GHashTable *_sf_prompt_text_from_variant_or_null(GVariant *variant)
{
    GHashTable *rv;
    GVariantIter i;
    gint32 key;
    gchar *value;

    g_variant_iter_init(&i, variant);
    if (!g_variant_iter_next(&i, "{is}", &key, &value))
        return NULL;
    rv = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    do {
        g_hash_table_replace(rv, GINT_TO_POINTER(key), value);
    } while (g_variant_iter_next(&i, "{is}", &key, &value));

    return rv;
}

static gboolean _sf_secrets_manager_perform_interaction(SfSecretsManager *manager,
        GDBusMethodInvocation *invocation,
        GVariant *args)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    gchar *id = g_uuid_string_random();
    gboolean *result;
    SfSecretsInteractionRequest *request;
    const gchar *secret_name;
    const gchar *collection_name;
    const gchar *plugin_name;
    const gchar *application_id;
    gint32 operation;
    const gchar *authentication_plugin_name;
    GVariant *prompt_text;
    GHashTable *pt;
    gint32 input_type;
    gint32 echo_mode;

    g_variant_get(args,
            "(&s&s&s&s(i)&s@a{is}(i)(i))",
            &secret_name,
            &collection_name,
            &plugin_name,
            &application_id,
            &operation,
            &authentication_plugin_name,
            &prompt_text,
            &input_type,
            &echo_mode);

    pt = _sf_prompt_text_from_variant_or_null(prompt_text);
    g_variant_unref(prompt_text);

    request = g_object_new(SF_TYPE_SECRETS_INTERACTION_REQUEST,
            "id", id,
            "invocation", invocation,
            "secret-name", secret_name,
            "collection-name", collection_name,
            "plugin-name", plugin_name,
            "application-id", application_id,
            "operation", operation,
            "authentication-plugin-name", authentication_plugin_name,
            "prompt-text", pt,
            "input-type", input_type,
            "echo-mode", echo_mode,
            NULL);
    g_object_add_weak_pointer(G_OBJECT(request), (gpointer *)&request);
    g_signal_emit(manager,
            _sf_secrets_manager_signals[SIGNAL_NEW_INTERACTION_REQUEST], 0,
            request,
            &result);
    g_object_unref(request);

    if (request) {
        request = g_object_ref(request);
        g_object_remove_weak_pointer(G_OBJECT(request), (gpointer *)&request);
        g_hash_table_insert(priv->requests, id, request);
        g_object_weak_ref(G_OBJECT(request), (GWeakNotify)_sf_secrets_manager_remove_request, manager);
        g_object_unref(request);
    } else {
        g_free(id);
    }

    if (pt)
        g_hash_table_unref(pt);

    return TRUE;
}

static gboolean _sf_secrets_manager_continue_interaction(SfSecretsManager *manager,
        GDBusMethodInvocation *invocation,
        const gchar *request_id,
        GVariant *request_params)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    SfSecretsInteractionRequest *request = g_hash_table_lookup(priv->requests, request_id);
    const gchar *secret_name;
    const gchar *collection_name;
    const gchar *plugin_name;
    const gchar *application_id;
    gint32 operation;
    const gchar *authentication_plugin_name;
    GVariant *prompt_text;
    gint32 input_type;
    gint32 echo_mode;
    GHashTable *pt;

    if (!request)
        return FALSE;

    g_variant_get(request_params,
            "(&s&s&s&s(i)&s@a{is}(i)(i))",
            &secret_name,
            &collection_name,
            &plugin_name,
            &application_id,
            &operation,
            &authentication_plugin_name,
            &prompt_text,
            &input_type,
            &echo_mode);

    pt = _sf_prompt_text_from_variant_or_null(prompt_text);

    g_object_freeze_notify(G_OBJECT(request));
    _sf_secrets_interaction_request_set(request,
            invocation,
            secret_name,
            collection_name,
            plugin_name,
            application_id,
            operation,
            authentication_plugin_name,
            pt,
            input_type,
            echo_mode);
    g_object_thaw_notify(G_OBJECT(request));

    if (pt)
        g_hash_table_unref(pt);

    g_signal_emit_by_name(request, "continue");

    return TRUE;
}

static gboolean _sf_secrets_manager_cancel_interaction(SfSecretsManager *manager,
        GDBusMethodInvocation *invocation,
        const gchar *request_id)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    SfSecretsInteractionRequest *request = g_hash_table_lookup(priv->requests, request_id);
    SfSecretsResultCode result = SF_SECRETS_RESULT_CODE_SUCCEEDED;
    SfSecretsError error = SF_SECRETS_ERROR_NO;
    const gchar *message = "";

    if (!request)
        return FALSE;

    g_object_add_weak_pointer(G_OBJECT(request), (gpointer *)&request);
    g_signal_emit_by_name(request, "cancel");

    if (request) {
        result = SF_SECRETS_RESULT_CODE_FAILED;
        error = SF_SECRETS_ERROR_INTERACTION_VIEW_UNAVAILABLE;
        message = "Cannot cancel ui request: view busy or no view registered";

        g_object_remove_weak_pointer(G_OBJECT(request), (gpointer *)&request);
    }

    g_dbus_method_invocation_return_value(invocation,
            g_variant_new("((iis))", result, error, message));

    return TRUE;
}

static gboolean _sf_secrets_manager_finish_interaction(SfSecretsManager *manager,
        GDBusMethodInvocation *invocation,
        const gchar *request_id)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    SfSecretsInteractionRequest *request = g_hash_table_lookup(priv->requests, request_id);
    SfSecretsResultCode result = SF_SECRETS_RESULT_CODE_SUCCEEDED;
    SfSecretsError error = SF_SECRETS_ERROR_NO;
    const gchar *message = "";

    if (!request)
        return FALSE;

    g_object_add_weak_pointer(G_OBJECT(request), (gpointer *)&request);
    g_signal_emit_by_name(request, "finish");

    if (request) {
        result = SF_SECRETS_RESULT_CODE_FAILED;
        error = SF_SECRETS_ERROR_INTERACTION_VIEW_UNAVAILABLE;
        message = "Cannot finish ui request: view busy or no view registered";
    }

    g_dbus_method_invocation_return_value(invocation,
            g_variant_new("((iis))", result, error, message));

    return TRUE;
}

static void _sf_secrets_manager_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *spec)
{
    SfSecretsManager *manager = SF_SECRETS_MANAGER(object);
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

    (void)spec;

    switch (property_id) {
        case PROP_APPLICATION_ID:
            if (priv->application_id)
                g_free(priv->application_id);
            priv->application_id = g_value_dup_string(value);
            break;
        case PROP_USER_INTERACTION_MODE:
            priv->user_interaction_mode_set = TRUE;
            if (priv->user_interaction_mode == g_value_get_uint(value))
                break;
            priv->user_interaction_mode = g_value_get_uint(value);

            if (priv->user_interaction_mode == SF_SECRETS_USER_INTERACTION_MODE_APPLICATION &&
                    g_signal_has_handler_pending(manager,
                        _sf_secrets_manager_signals[SIGNAL_NEW_INTERACTION_REQUEST],
                        0, TRUE))
                g_warning("User interaction mode set to application, but no handler registered");

            if (priv->server) {
                if (priv->user_interaction_mode == SF_SECRETS_USER_INTERACTION_MODE_APPLICATION)
                    g_dbus_server_start(priv->server);
                else
                    g_dbus_server_stop(priv->server);
            } else if (priv->user_interaction_mode == SF_SECRETS_USER_INTERACTION_MODE_APPLICATION) {
                gchar *guid = g_dbus_generate_guid();
                priv->connections = g_hash_table_new_full(g_direct_hash,
                        g_direct_equal,
                        g_object_unref,
                        NULL);
                priv->requests = g_hash_table_new_full(g_str_hash,
                        g_str_equal, (GDestroyNotify)g_free, NULL);
                priv->interaction_service_address = g_strdup_printf("unix:path=%s/interaction-bus-%u",
                        g_get_user_runtime_dir(),
                        (guint)getpid());
                priv->server = g_dbus_server_new_sync(priv->interaction_service_address,
                        G_DBUS_SERVER_FLAGS_AUTHENTICATION_ALLOW_ANONYMOUS,
                        guid,
                        NULL,
                        NULL,
                        NULL);
                priv->interaction_interface = sf_secrets_interaction_skeleton_new();

                g_signal_connect_swapped(priv->interaction_interface,
                        "handle-perform-interaction-request",
                        G_CALLBACK(_sf_secrets_manager_perform_interaction),
                        manager);
                g_signal_connect_swapped(priv->interaction_interface,
                        "handle-continue-interaction-request",
                        G_CALLBACK(_sf_secrets_manager_continue_interaction),
                        manager);
                g_signal_connect_swapped(priv->interaction_interface,
                        "handle-cancel-interaction-request",
                        G_CALLBACK(_sf_secrets_manager_cancel_interaction),
                        manager);
                g_signal_connect_swapped(priv->interaction_interface,
                        "handle-finish-interaction-request",
                        G_CALLBACK(_sf_secrets_manager_finish_interaction),
                        manager);

                g_free(guid);

                g_dbus_server_start(priv->server);

                g_signal_connect_object(priv->server,
                        "new-connection",
                        G_CALLBACK(_sf_secrets_manager_new_interaction_connection),
                        object,
                        G_CONNECT_SWAPPED);
            }
            break;
        default:
            g_warning("Unknown property %u", property_id);
            break;
    }
}

static gboolean _sf_secrets_manager_interaction_request_unhandled(SfSecretsManager *manager,
        SfSecretsInteractionRequest *request)
{
    GError *error = g_error_new(SF_SECRETS_ERROR,
            SF_SECRETS_ERROR_INTERACTION_VIEW_UNAVAILABLE,
            "Unhandled");

    (void)manager;

    sf_secrets_interaction_request_return_error(request, error);

    return TRUE;
}

static void sf_secrets_manager_class_init(SfSecretsManagerClass *manager_class)
{
    G_OBJECT_CLASS(manager_class)->finalize = _sf_secrets_manager_finalize;
    G_OBJECT_CLASS(manager_class)->set_property = _sf_secrets_manager_set_property;
    G_OBJECT_CLASS(manager_class)->get_property = _sf_secrets_manager_get_property;

    _sf_secrets_manager_signals[SIGNAL_NEW_INTERACTION_REQUEST] = g_signal_new_class_handler(
            "new-interaction-request",
            SF_TYPE_SECRETS_MANAGER,
            G_SIGNAL_RUN_LAST,
            G_CALLBACK(_sf_secrets_manager_interaction_request_unhandled),
            g_signal_accumulator_true_handled,
            NULL,
            NULL,
            G_TYPE_BOOLEAN,
            1,
            SF_TYPE_SECRETS_INTERACTION_REQUEST);

    g_object_class_install_property(G_OBJECT_CLASS(manager_class),
            PROP_APPLICATION_ID,
            g_param_spec_string("application-id",
                "application-id",
                "Application ID",
                NULL,
                G_PARAM_READWRITE |
                G_PARAM_STATIC_STRINGS));

    g_object_class_install_property(G_OBJECT_CLASS(manager_class),
            PROP_USER_INTERACTION_MODE,
            g_param_spec_uint("user-interaction-mode",
                "user-interaction-mode",
                "User interaction mode",
                SF_SECRETS_USER_INTERACTION_MODE_PREVENT,
                SF_SECRETS_USER_INTERACTION_MODE_APPLICATION,
                SF_SECRETS_USER_INTERACTION_MODE_PREVENT,
                G_PARAM_READWRITE |
                G_PARAM_STATIC_STRINGS));
}


SfSecretsManager *sf_secrets_manager_new_finish(GAsyncResult *res,
        GError **error)
{
    GObject *src_obj = g_async_result_get_source_object(res);
    GObject *obj = g_async_initable_new_finish(G_ASYNC_INITABLE(src_obj),
            res, error);
    g_object_unref(src_obj);

    return SF_SECRETS_MANAGER(obj);
}

void sf_secrets_manager_new(GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    g_async_initable_new_async(SF_TYPE_SECRETS_MANAGER,
            G_PRIORITY_DEFAULT,
            cancellable,
            callback,
            user_data,
            NULL);
}

static void _sf_secrets_manager_proxy_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    SfSecretsManager *secrets = g_task_get_source_object(task);
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(secrets);
    GError *error = NULL;

    (void)source_object;

    priv->proxy = g_dbus_proxy_new_finish(res, &error);

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_task_return_boolean(task, TRUE);
    g_object_unref(task);
}

void _sf_secrets_manager_connection_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GDBusConnection *connection = g_dbus_connection_new_for_address_finish(res, &error);

    (void)source_object;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_task_set_task_data(task, connection, g_object_unref);

    g_dbus_proxy_new(connection,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL, NULL,
            "/Sailfish/Secrets",
            "org.sailfishos.secrets",
            g_task_get_cancellable(task),
            _sf_secrets_manager_proxy_ready,
            task);
}

void _sf_secrets_manager_discovery_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
            res, &error);
    const gchar *address = NULL;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_variant_get(response, "(&s)", &address);

    if (!address) {
        g_variant_unref(response);
        g_task_return_new_error(task,
                SF_SECRETS_ERROR,
                SF_SECRETS_ERROR_DAEMON, "Daemon sent a reply we didn't understand");
        g_object_unref(task);
        return;
    }

    g_task_set_task_data(task, NULL, NULL);
    g_dbus_connection_new_for_address(address,
            G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
            NULL,
            g_task_get_cancellable(task),
            _sf_secrets_manager_connection_ready,
            task);
    g_variant_unref(response);
}

void _sf_secrets_manager_discovery_proxy_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GDBusProxy *dproxy = g_dbus_proxy_new_for_bus_finish(res, &error);

    (void)source_object;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_task_set_task_data(task, dproxy, g_object_unref);

    g_dbus_proxy_call(
            dproxy,
            "peerToPeerAddress",
            g_variant_new("()"),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            g_task_get_cancellable(task),
            _sf_secrets_manager_discovery_ready,
            task);
}

static void _async_initable_init_async (GAsyncInitable *initable,
        gint io_priority,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    GTask *task = g_task_new(initable, cancellable, callback, user_data);

    g_task_set_priority(task, io_priority);

    g_dbus_proxy_new_for_bus(
            G_BUS_TYPE_SESSION,
            G_DBUS_PROXY_FLAGS_NONE,
            NULL, /* info */
            "org.sailfishos.secrets.daemon.discovery",
            "/Sailfish/Secrets/Discovery",
            "org.sailfishos.secrets.daemon.discovery",
            cancellable,
            _sf_secrets_manager_discovery_proxy_ready,
            task);
}

static gboolean _async_initable_init_finish (GAsyncInitable *initable,
        GAsyncResult *res,
        GError **error)
{
    (void)initable;
    return g_task_propagate_boolean(G_TASK(res), error);
}

GDBusProxy *_sf_secrets_manager_get_dbus_proxy(SfSecretsManager *manager)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    return g_object_ref(priv->proxy);
}

gboolean _sf_secrets_manager_check_reply(GVariant *response, GError **error, GVariantIter *iter)
{
    GVariantIter i;
    GVariant *result;
    gint32 result_code;
    gint32 error_code;
    const gchar *error_msg;
    gboolean res = TRUE;

    if (!iter)
        iter = &i;

    g_variant_iter_init(iter, response);
    result = g_variant_iter_next_value(iter);
    g_variant_get(result, "(ii&s)", &result_code, &error_code, &error_msg);

    if (result_code != SF_SECRETS_RESULT_CODE_SUCCEEDED) {
        g_set_error(error,
                SF_SECRETS_ERROR,
                error_code, "%s", error_msg);
        res = FALSE;
    }

    g_variant_unref(result);

    return res;
}

static GVariant *_sf_secrets_manager_dbus_call_finish(GObject *source_object,
        GAsyncResult *res,
        GError **error,
        GVariantIter *iter)
{
    GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
            res, error);

    if (!response)
        return response;

    if (!_sf_secrets_manager_check_reply(response, error, iter)) {
        g_variant_unref(response);
        return NULL;
    }

    return response;
}

void _sf_secrets_manager_result_only_ready(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GVariant *response = _sf_secrets_manager_dbus_call_finish(source_object, res, &error, NULL);

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_variant_unref(response);
    g_task_return_boolean(task, TRUE);
    g_object_unref(task);
}


static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
    async_initable_iface->init_async = _async_initable_init_async;
    async_initable_iface->init_finish = _async_initable_init_finish;
}

static void _sf_secrets_manager_get_plugin_info_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GVariantIter iter;
    GVariant *response = _sf_secrets_manager_dbus_call_finish(source_object, res, &error, &iter);

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_task_set_task_data(task, response, (GDestroyNotify)g_variant_unref);
    g_task_return_pointer(task, g_variant_iter_copy(&iter), (GDestroyNotify)g_variant_iter_free);
    g_object_unref(task);
}

void sf_secrets_manager_get_plugin_info(SfSecretsManager *manager,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    GTask *task = g_task_new(manager, cancellable, callback, user_data);
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

    g_dbus_proxy_call(priv->proxy,
            "getPluginInfo",
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            g_task_get_cancellable(task),
            _sf_secrets_manager_get_plugin_info_ready,
            task);
}

gboolean sf_secrets_manager_get_plugin_info_finish(GAsyncResult *res,
        GSList **storage_plugins,
        GSList **encryption_plugins,
        GSList **encrypted_storage_plugins,
        GSList **authentication_plugins,
        GError **error)
{
    gsize i;
    GSList **plugin_lists[] = {
        storage_plugins,
        encryption_plugins,
        encrypted_storage_plugins,
        authentication_plugins
    };

    GVariantIter *iter = g_task_propagate_pointer(G_TASK(res), error);

    if (!iter)
        return FALSE;

    for (i = 0; i < G_N_ELEMENTS(plugin_lists); i++) {
        GVariant *array = g_variant_iter_next_value(iter);
        GVariantIter array_iter;
        SfSecretsPluginInfo info;
        gint32 state;

        if (!plugin_lists[i]) {
            g_variant_unref(array);
            continue;
        }

        *plugin_lists[i] = NULL;
        g_variant_iter_init(&array_iter, array);
        while (g_variant_iter_loop(&array_iter, "(&s&sii)",
                    &info.display_name,
                    &info.name,
                    &info.version,
                    &state)) {
            info.state = state;
            *plugin_lists[i] = g_slist_append(*plugin_lists[i], sf_secrets_plugin_info_copy(&info));
        }
        g_variant_unref(array);
    }

    g_variant_iter_free(iter);

    return TRUE;
}

void _sf_secrets_manager_get_health_info_reply(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GVariantIter iter;
    GVariant *ret = _sf_secrets_manager_dbus_call_finish(source_object, res, &error, &iter);

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_task_set_task_data(task, ret, (GDestroyNotify)g_variant_unref);
    g_task_return_pointer(task, g_variant_iter_copy(&iter), (GDestroyNotify)g_variant_iter_free);
    g_object_unref(task);
}

void sf_secrets_manager_get_health_info(SfSecretsManager *manager,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);

    g_dbus_proxy_call(priv->proxy,
            "getHealthInfo",
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_secrets_manager_get_health_info_reply,
            task);
}

gboolean sf_secrets_manager_get_health_info_finish(GAsyncResult *res,
        gboolean *is_healthy,
        SfSecretsHealth *salt_data_health,
        SfSecretsHealth *master_lock_health,
        GError **error)
{
    GVariantIter *ret = g_task_propagate_pointer(G_TASK(res), error);

    gint32 sd_health;
    gint32 ml_health;

    g_variant_iter_next(ret, "(i)",
            &sd_health);
    g_variant_iter_next(ret, "(i)",
            &ml_health);

    if (salt_data_health)
        *salt_data_health = sd_health;
    if (master_lock_health)
        *master_lock_health = ml_health;
    if (is_healthy)
        *is_healthy = sd_health == SF_SECRETS_HEALTH_OK &&
            ml_health == SF_SECRETS_HEALTH_OK;

    g_variant_iter_free(ret);

    if (!ret)
        return FALSE;
    return TRUE;
}

static void _sf_secrets_manager_collection_names_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GVariantIter iter;
    GTask *task = user_data;
    GError *error = NULL;
    GVariant *response = _sf_secrets_manager_dbus_call_finish(source_object, res, &error, &iter);
    GVariant *namemap;
    GVariantIter mapiter;
    GArray *names;
    gchar *name;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    names = g_array_new(TRUE, FALSE, sizeof(gchar *));
    namemap = g_variant_iter_next_value(&iter);
    g_variant_iter_init(&mapiter, namemap);
    while (g_variant_iter_next(&mapiter, "{sv}", &name, NULL))
        g_array_append_val(names, name);
    g_variant_unref(namemap);
    g_variant_unref(response);

    g_task_return_pointer(task, g_array_free(names, FALSE), (GDestroyNotify)g_strfreev);
    g_object_unref(task);
}

void sf_secrets_manager_collection_names(SfSecretsManager *manager,
        const gchar *plugin_name,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);

    g_dbus_proxy_call(priv->proxy,
            "collectionNames",
            g_variant_new("(s)", plugin_name),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_secrets_manager_collection_names_ready,
            task);
}

gchar **sf_secrets_manager_collection_names_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_pointer(G_TASK(res), error);
}

static void _sf_secrets_manager_create_collection_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GVariant *response = _sf_secrets_manager_dbus_call_finish(source_object, res, &error, NULL);

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_variant_unref(response);
    g_task_return_boolean(task, TRUE);
    g_object_unref(task);
}

void sf_secrets_manager_create_collection(SfSecretsManager *manager,
        const gchar *plugin_name,
        const gchar *encryption_plugin_name,
        const gchar *authentication_plugin_name,
        const gchar *name,
        SfSecretsDeviceUnlockSemantic unlock_semantic,
        SfSecretsAccessControlMode access_control_mode,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);
    GVariant *args;

    if (authentication_plugin_name && *authentication_plugin_name) {
        args = g_variant_new("(ssss(i)(i)(i)s)",
                name,
                plugin_name,
                encryption_plugin_name,
                authentication_plugin_name,
                unlock_semantic,
                access_control_mode,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address));
    } else {
        args = g_variant_new("(sss(i)(i))",
                name,
                plugin_name,
                encryption_plugin_name,
                unlock_semantic,
                access_control_mode);
    }

    g_dbus_proxy_call(priv->proxy,
            "createCollection",
            args,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            g_task_get_cancellable(task),
            _sf_secrets_manager_create_collection_ready,
            task);
}

gboolean sf_secrets_manager_create_collection_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_secrets_manager_delete_collection_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    _sf_secrets_manager_result_only_ready(source_object, res, user_data);
}

void sf_secrets_manager_delete_collection(SfSecretsManager *manager,
        const gchar *plugin_name,
        const gchar *collection_name,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);

    g_dbus_proxy_call(priv->proxy,
            "deleteCollection",
            g_variant_new("(ss(i)s)",
                collection_name,
                plugin_name,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address)),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            g_task_get_cancellable(task),
            _sf_secrets_manager_delete_collection_ready,
            task);
}

gboolean sf_secrets_manager_delete_collection_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_secrets_manager_set_secret_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    _sf_secrets_manager_result_only_ready(source_object, res, user_data);
}

void sf_secrets_manager_set_secret(SfSecretsManager *manager,
        SfSecretsSecret *secret,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);

    GBytes *data;
    GVariant *secret_data;

    GHashTable *filter_hash;
    GVariant *filters;

    g_object_ref_sink(secret);

    if (G_UNLIKELY(!sf_secrets_secret_get_collection_name(secret))) {
        g_task_return_new_error(task,
                SF_SECRETS_ERROR,
                    SF_SECRETS_ERROR_INVALID_COLLECTION,
                    "sf_secrets_manager_set_secret called with standalone secret");
        g_object_unref(task);
        g_object_unref(secret);
        return;
    }

    g_object_get(secret,
        "data", &data,
        "filter-fields", &filter_hash, NULL);

    secret_data = _sf_variant_new_bytes_or_empty(data);
    if (data)
        g_bytes_unref(data);

    filters = _sf_variant_new_variant_map_string_or_empty(filter_hash);
    if (filter_hash)
        g_hash_table_unref(filter_hash);

    g_dbus_proxy_call(priv->proxy,
            "setSecret",
            g_variant_new("(((sss)@ay@a{sv})(ssss(i)s@a{is}(i)(i))(i)s)",
                sf_secrets_secret_get_name(secret),
                sf_secrets_secret_get_collection_name(secret),
                sf_secrets_secret_get_plugin_name(secret),
                secret_data,
                filters,
                "", "", "", "", 0, "", g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0), 0, 0,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address)),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            g_task_get_cancellable(task),
            _sf_secrets_manager_set_secret_ready,
            task);

    g_object_unref(secret);
}

void sf_secrets_manager_set_secret_standalone(SfSecretsManager *manager,
        SfSecretsSecret *secret,
        const gchar *encryption_plugin_name,
        const gchar *authentication_plugin_name,
        SfSecretsDeviceUnlockSemantic device_unlock_semantic,
        SfSecretsAccessControlMode access_control_mode,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);
    GVariant *args;

    GBytes *data;
    GVariant *secret_data;

    GHashTable *filter_hash;
    GVariant *filters;

    g_object_ref_sink(secret);

    if (G_UNLIKELY(sf_secrets_secret_get_collection_name(secret))) {
        g_task_return_new_error(task,
                SF_SECRETS_ERROR,
                    SF_SECRETS_ERROR_INVALID_COLLECTION,
                    "sf_secrets_manager_set_secret_standalone called with collection secret");
        g_object_unref(task);
        g_object_unref(secret);

        return;
    }

    g_object_get(secret,
        "data", &data,
        "filter-fields", &filter_hash, NULL);

    secret_data = _sf_variant_new_bytes_or_empty(data);
    if (data)
        g_bytes_unref(data);

    filters = _sf_variant_new_variant_map_string_or_empty(filter_hash);
    if (filter_hash)
        g_hash_table_unref(filter_hash);


    if (authentication_plugin_name && *authentication_plugin_name) {
        args = g_variant_new("("
                "((sss)@ay@a{sv})"
                "ss"
                "(ssss(i)s@a{is}(i)(i))"
                "(i)(i)(i)s"
                ")",
                sf_secrets_secret_get_name(secret),
                "",
                sf_secrets_secret_get_plugin_name(secret),
                secret_data,
                filters,
                encryption_plugin_name,
                authentication_plugin_name,
                "", "", "", "", 0, "", g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0), 0, 0,
                device_unlock_semantic,
                access_control_mode,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address));
    } else {
        args = g_variant_new("(((sss)@ay@a{sv})s(ssss(i)s@a{is}(i)(i))(i)(i)(i)s)",
                sf_secrets_secret_get_name(secret),
                "",
                sf_secrets_secret_get_plugin_name(secret),
                secret_data,
                filters,
                encryption_plugin_name,
                "", "", "", "", 0, "", g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0), 0, 0,
                device_unlock_semantic,
                access_control_mode,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address));
    }

    g_dbus_proxy_call(priv->proxy,
            "setSecret",
            args,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            g_task_get_cancellable(task),
            _sf_secrets_manager_set_secret_ready,
            task);

    g_object_unref(secret);
}


gboolean sf_secrets_manager_set_secret_finish(GAsyncResult *res, GError **error)
{
    return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_secrets_manager_delete_secret_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    _sf_secrets_manager_result_only_ready(source_object, res, user_data);
}

void sf_secrets_manager_delete_secret_by_name(SfSecretsManager *manager,
        const gchar *name,
        const gchar *collection_name,
        const gchar *plugin_name,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);

    g_dbus_proxy_call(priv->proxy,
            "deleteSecret",
            g_variant_new("((sss)(i)s)",
                name,
                EMPTY_IF_NULL(collection_name),
                plugin_name,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address)),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            g_task_get_cancellable(task),
            _sf_secrets_manager_delete_secret_ready,
            task);
}

void sf_secrets_manager_delete_secret(SfSecretsManager *manager,
        SfSecretsSecret *secret,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    sf_secrets_manager_delete_secret_by_name(manager,
            sf_secrets_secret_get_name(secret),
            sf_secrets_secret_get_collection_name(secret),
            sf_secrets_secret_get_plugin_name(secret),
            cancellable,
            callback,
            user_data);
}

gboolean sf_secrets_manager_delete_secret_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_boolean(G_TASK(res), error);
}

void _sf_secrets_manager_query_lock_status_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GVariantIter iter;
    GVariant *ret = _sf_secrets_manager_dbus_call_finish(source_object, res, &error, &iter);
    gint32 status;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_variant_iter_next(&iter, "(i)", &status);
    g_variant_unref(ret);
    g_task_return_int(task, status);
    g_object_unref(task);
}

void sf_secrets_manager_query_lock_status(SfSecretsManager *manager,
        SfSecretsLockCodeTargetType target_type,
        const gchar *target,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);

    g_dbus_proxy_call(priv->proxy,
            "queryLockStatus",
            g_variant_new("((i)s)",
                (gint32)target_type,
                target),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_secrets_manager_query_lock_status_ready,
            task);
}

SfSecretsLockStatus sf_secrets_manager_query_lock_status_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_int(G_TASK(res), error);
}

static void _sf_secrets_manager_lock_code_request_reply(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    _sf_secrets_manager_result_only_ready(source_object, res, user_data);
}

static void _sf_secrets_manager_lock_code_request(SfSecretsManager *manager,
        const gchar *method,
        SfSecretsLockCodeTargetType target_type,
        const gchar *target,
        const gchar *authentication_plugin_name,
        SfSecretsInputType input_type,
        SfSecretsEchoMode echo_mode,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);

    g_dbus_proxy_call(priv->proxy,
            method,
            g_variant_new("((i)s(ssss(i)sa{is}(i)(i))(i)s)",
                target_type,
                EMPTY_IF_NULL(target),
                "", "", "",
                authentication_plugin_name,
                0, "",
                g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0),
                input_type,
                echo_mode,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address)),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_secrets_manager_lock_code_request_reply,
            task);
}

void sf_secrets_manager_modify_lock_code(SfSecretsManager *manager,
        SfSecretsLockCodeTargetType target_type,
        const gchar *target,
        const gchar *authentication_plugin_name,
        SfSecretsInputType input_type,
        SfSecretsEchoMode echo_mode,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    _sf_secrets_manager_lock_code_request(manager,
            "modifyLockCode",
            target_type,
            target,
            authentication_plugin_name,
            input_type,
            echo_mode,
            cancellable,
            callback,
            user_data);
}

gboolean sf_secrets_manager_modify_lock_code_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_boolean(G_TASK(res), error);
}

void sf_secrets_manager_provide_lock_code(SfSecretsManager *manager,
        SfSecretsLockCodeTargetType target_type,
        const gchar *target,
        const gchar *authentication_plugin_name,
        SfSecretsInputType input_type,
        SfSecretsEchoMode echo_mode,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    _sf_secrets_manager_lock_code_request(manager,
            "provideLockCode",
            target_type,
            target,
            authentication_plugin_name,
            input_type,
            echo_mode,
            cancellable,
            callback,
            user_data);
}

gboolean sf_secrets_manager_provide_lock_code_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_boolean(G_TASK(res), error);
}

void sf_secrets_manager_forget_lock_code(SfSecretsManager *manager,
        SfSecretsLockCodeTargetType target_type,
        const gchar *target,
        const gchar *authentication_plugin_name,
        SfSecretsInputType input_type,
        SfSecretsEchoMode echo_mode,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    _sf_secrets_manager_lock_code_request(manager,
            "forgetLockCode",
            target_type,
            target,
            authentication_plugin_name,
            input_type,
            echo_mode,
            cancellable,
            callback,
            user_data);
}

gboolean sf_secrets_manager_forget_lock_code_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_secrets_manager_get_secret_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    SfSecretsManager *manager = g_task_get_source_object(task);
    GError *error = NULL;
    GVariantIter iter;
    GVariant *response = _sf_secrets_manager_dbus_call_finish(source_object,
            res, &error, &iter);
    GVariant *array;
    GVariant *fields;
    GBytes *secret_bytes;
    GHashTable *filter_fields;
    SfSecretsSecret *secret;
    const gchar *identifier;
    const gchar *collection_name;
    const gchar *plugin_name;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    g_variant_iter_next(&iter, "((&s&s&s)@ay@a{sv})",
            &identifier,
            &collection_name,
            &plugin_name,
            &array,
            &fields);

    secret_bytes = _sf_bytes_new_from_variant_or_null(array);
    filter_fields = _sf_hash_table_new_string_from_variant(fields);

    secret = g_object_new(SF_TYPE_SECRETS_SECRET,
            "manager", manager,
            "plugin-name", plugin_name,
            "collection-name", collection_name,
            "name", identifier,
            "data", secret_bytes,
            "filter-fields", filter_fields,
            NULL);

    g_variant_unref(array);
    g_variant_unref(fields);
    g_variant_unref(response);
    if (secret_bytes)
        g_bytes_unref(secret_bytes);
    if (filter_fields)
        g_hash_table_unref(filter_fields);

    g_task_return_pointer(task, secret, g_object_unref);
    g_object_unref(task);
}

void sf_secrets_manager_get_secret(SfSecretsManager *manager,
        const gchar *name,
        const gchar *collection_name,
        const gchar *plugin_name,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
    GTask *task = g_task_new(manager, cancellable, callback, user_data);

    g_dbus_proxy_call(priv->proxy,
            "getSecret",
            g_variant_new("((sss)(i)s)",
                name,
                EMPTY_IF_NULL(collection_name),
                plugin_name,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address)),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            g_task_get_cancellable(task),
            _sf_secrets_manager_get_secret_ready,
            task);
}

SfSecretsSecret *sf_secrets_manager_get_secret_finish(GAsyncResult *res,
        GError **error)
{
    return g_task_propagate_pointer(G_TASK(res), error);
}


static void _sf_secrets_manager_find_secrets_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    GTask *task = user_data;
    GError *error = NULL;
    GArray *secret_names;
    GVariantIter iter;
    GVariant *response = _sf_secrets_manager_dbus_call_finish(source_object, res, &error, &iter);
    GVariant *secrets;
    GVariantIter secret_iter;
    gchar *secret_name;

    if (error) {
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    secret_names = g_array_new(TRUE, FALSE, sizeof(gchar *));
    secrets = g_variant_iter_next_value(&iter);

    g_variant_iter_init(&secret_iter, secrets);
    while (g_variant_iter_next(&secret_iter, "(s&s&s)",
                &secret_name,
                NULL,
                NULL))
        g_array_append_val(secret_names, secret_name);
    g_variant_unref(secrets);
    g_variant_unref(response);

    g_task_return_pointer(task, g_array_free(secret_names, FALSE), (GDestroyNotify)g_strfreev);
    g_object_unref(task);
}

static void _sf_secrets_manager_find_secrets_vb(SfSecretsManager *manager,
        const gchar *collection_name,
        const gchar *plugin_name,
        GVariantBuilder *filters,
        SfSecretsFilterOperator op,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    GTask *task = g_task_new(manager, cancellable, callback, user_data);
    SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

    g_dbus_proxy_call(priv->proxy,
            "findSecrets",
            g_variant_new("(ssa{ss}(i)(i)s)",
                collection_name,
                plugin_name,
                filters,
                (gint)op,
                priv->user_interaction_mode,
                EMPTY_IF_NULL(priv->interaction_service_address)),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            cancellable,
            _sf_secrets_manager_find_secrets_ready,
            task);
}

void sf_secrets_manager_find_secrets_va(SfSecretsManager *manager,
        const gchar *collection_name,
        const gchar *plugin_name,
        SfSecretsFilterOperator op,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data,
        const gchar *first_filter_name,
        va_list args)
{
    GVariantBuilder filters;

    g_variant_builder_init(&filters, G_VARIANT_TYPE("a{ss}"));
    while (first_filter_name) {
        const gchar *filter_arg = va_arg(args, const gchar *);
        g_variant_builder_add(&filters, "{ss}", first_filter_name, filter_arg);
        first_filter_name = va_arg(args, const gchar *);
    }

    _sf_secrets_manager_find_secrets_vb(manager, collection_name, plugin_name,
            &filters, op, cancellable, callback, user_data);
}

void sf_secrets_manager_find_secrets_ht(SfSecretsManager *manager,
        const gchar *collection_name,
        const gchar *plugin_name,
        GHashTable *filters,
        SfSecretsFilterOperator op,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    GVariantBuilder builder;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));

    if (filters) {
        GHashTableIter iter;
        gpointer key;
        gpointer value;

        g_hash_table_iter_init(&iter, filters);
        while (g_hash_table_iter_next(&iter, &key, &value))
            g_variant_builder_add(&builder, "{ss}", key, value);
    }

    _sf_secrets_manager_find_secrets_vb(manager, collection_name, plugin_name,
            &builder, op,
            cancellable, callback, user_data);
}

void sf_secrets_manager_find_secrets(SfSecretsManager *manager,
        const gchar *collection_name,
        const gchar *plugin_name,
        SfSecretsFilterOperator op,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data,
        const gchar *first_filter_name,
        ...)
{
    va_list args;
    va_start(args, first_filter_name);
    sf_secrets_manager_find_secrets_va(manager, collection_name, plugin_name,
            op, cancellable, callback, user_data, first_filter_name, args);
    va_end(args);
}

gchar **sf_secrets_manager_find_secrets_finish(GAsyncResult *res, GError **error)
{
    return g_task_propagate_pointer(G_TASK(res), error);
}
