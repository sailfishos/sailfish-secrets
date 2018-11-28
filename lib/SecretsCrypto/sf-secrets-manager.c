#include "sf-secrets.h"
#include "sf-secrets-manager.h"
#include "sf-secrets-manager-private.h"
#include "sf-secrets-interaction.h"
#include "sf-secrets-interaction-request.h"

typedef struct SfSecretsManagerPrivate_ SfSecretsManagerPrivate;
typedef enum SfSecretsManagerSignal_ {
	SIGNAL_NEW_INTERACTION_REQUEST,
	SIGNAL_COUNT
} SfSecretsManagerSignal;

static guint _sf_secrets_manager_signals[SIGNAL_COUNT];

struct SfSecretsManagerPrivate_
{
	GDBusProxy *proxy;
	/*
	GSList *plugins[SF_SECRET_PLUGIN_TYPE_COUNT];
	*/
	gchar *application_id;
	gboolean user_interaction_mode_set;
	SfSecretsUserInteractionMode user_interaction_mode;

	SfSecretsInteraction *interaction_interface;
	gchar *interaction_service_address;
	GDBusServer *server;
	GHashTable *connections;
	GHashTable *requests;
};

static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface);
static void _async_initable_init_async (GAsyncInitable *initable,
		gint io_priority,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
static gboolean _async_initable_init_finish (GAsyncInitable *initable,
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

static void _sf_secrets_manager_finalize(GObject *object)
{
	SfSecretsManager *manager = SF_SECRETS_MANAGER(object);
	SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
	/*
	int i;
	*/

	if (priv->proxy)
		g_object_unref(priv->proxy);

	if (priv->server)
		g_object_unref(priv->server);

	if (priv->connections)
		g_hash_table_unref(priv->connections);

	if (priv->interaction_service_address)
		g_free(priv->interaction_service_address);

	if (priv->interaction_interface)
		g_object_unref(priv->interaction_interface);

	if (priv->application_id)
		g_free(priv->application_id);

	/*
	for (i = 0; i < SF_SECRET_PLUGIN_TYPE_COUNT; i++) {
		g_slist_foreach(priv->plugins[i], (GFunc)sf_secrets_plugin_info_free, NULL);
		g_slist_free(priv->plugins[i]);
	}
	*/
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

static gboolean _sf_secrets_manager_ptr_equal(gpointer key, gpointer value, gpointer user_data)
{
	(void)key;
	return value == user_data;
}

static void _sf_secrets_manager_remove_request(SfSecretsManager *manager,
		SfSecretsInteractionRequest *gone_request)
{
	SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

	g_hash_table_foreach_steal(priv->requests, _sf_secrets_manager_ptr_equal, gone_request);
}

static gboolean _sf_secrets_manager_perform_interaction(SfSecretsManager *manager,
		GDBusMethodInvocation *invocation,
		GVariant *args)
{
	SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
	gchar *id = g_uuid_string_random();
	gboolean *result;
	SfSecretsInteractionRequest *request = g_object_new(SF_TYPE_SECRETS_INTERACTION_REQUEST,
			"id", id,
			"invocation", invocation,
			NULL);

	(void)args;

	g_object_add_weak_pointer(G_OBJECT(request), (gpointer *)&request);
	g_signal_emit(manager,
			_sf_secrets_manager_signals[SIGNAL_NEW_INTERACTION_REQUEST], 0,
			request,
			&result);
	g_object_unref(request);

	if ((request = g_object_ref(request))) {
		g_object_remove_weak_pointer(G_OBJECT(request), (gpointer *)&request);
		g_hash_table_insert(priv->requests, id, request);
		g_object_weak_ref(G_OBJECT(request), (GWeakNotify)_sf_secrets_manager_remove_request, manager);
		g_object_unref(request);
	}

	return TRUE;
}

static gboolean _sf_secrets_manager_continue_interaction(SfSecretsManager *manager,
		GDBusMethodInvocation *invocation,
		const gchar *request_id,
		GVariant *request_params)
{
	SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
	SfSecretsInteractionRequest *request = g_hash_table_lookup(priv->requests, request_id);

	(void)request_params;

	if (!request)
		return FALSE;

	g_object_set(request,
			"invocation", invocation,
			NULL);
	g_signal_emit_by_name(request, "continue");

	return TRUE;
}

static gboolean _sf_secrets_manager_cancel_interaction(SfSecretsManager *manager,
		GDBusMethodInvocation *invocation,
		const gchar *request_id)
{
	SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
	SfSecretsInteractionRequest *request = g_hash_table_lookup(priv->requests, request_id);

	if (!request)
		return FALSE;

	g_hash_table_remove(priv->requests, request_id);
	g_object_weak_unref(G_OBJECT(request), (GWeakNotify)_sf_secrets_manager_remove_request, manager);
	g_object_set(request,
			"invocation", invocation,
			NULL);
	g_signal_emit_by_name(request, "cancel");

	return TRUE;
}

static gboolean _sf_secrets_manager_finish_interaction(SfSecretsManager *manager,
		GDBusMethodInvocation *invocation,
		const gchar *request_id)
{
	SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);
	SfSecretsInteractionRequest *request = g_hash_table_lookup(priv->requests, request_id);

	if (!request)
		return FALSE;

	g_hash_table_remove(priv->requests, request_id);
	g_object_weak_unref(G_OBJECT(request), (GWeakNotify)_sf_secrets_manager_remove_request, manager);
	g_object_set(request,
			"invocation", invocation,
			NULL);
	g_signal_emit_by_name(request, "finish");

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
				priv->requests = g_hash_table_new(g_str_hash,
						g_str_equal);
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
	GError *error = g_error_new(g_quark_from_static_string("SfSecrets"),
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


gboolean sf_secrets_manager_get_health_info_finish(GAsyncResult *res,
		gboolean *is_healthy,
		SfSecretsHealth *salt_data_health,
		SfSecretsHealth *master_lock_health,
		GError **error)
{
	GVariant *ret = g_task_propagate_pointer(G_TASK(res), error);

	gint32 sd_health;
	gint32 ml_health;

	g_variant_get(ret, "((i)(i))",
			&sd_health,
			&ml_health);

	if (salt_data_health)
		*salt_data_health = sd_health;
	if (master_lock_health)
		*master_lock_health = ml_health;
	if (is_healthy)
		*is_healthy = sd_health == SF_SECRETS_HEALTH_OK &&
			ml_health == SF_SECRETS_HEALTH_OK;

	g_variant_unref(ret);

	if (!ret)
		return FALSE;
	return TRUE;
}

void _sf_secrets_manager_get_health_info_reply(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariant *ret = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object), res, &error);

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	if (!_sf_secrets_manager_check_reply(ret, &error, NULL)) {
		g_task_return_error(task, error);
		g_object_unref(task);
		g_variant_unref(ret);
		return;
	}

	g_task_return_pointer(task, ret, (GDestroyNotify)g_variant_unref);
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

static void _sf_secrets_manager_get_plugin_info_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	/*
	SfSecretsManager *secrets = g_task_get_source_object(task);
	SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(secrets);
	*/
	GError *error = NULL;
	GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
			res, &error);
	GVariantIter iter;
	/*
	int i;
	*/

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	if (!_sf_secrets_manager_check_reply(response, &error, &iter)) {
		g_task_return_error(task, error);
		g_object_unref(task);
		g_variant_unref(response);
		return;
	}

	/*
	for (i = 0; i < SF_SECRET_PLUGIN_TYPE_COUNT; i++) {
		GVariant *array = g_variant_iter_next_value(&iter);
		GVariantIter array_iter;
		SfSecretsPluginInfo info;
		gint32 state;

		if (!array)
			break;

		g_variant_iter_init(&array_iter, array);
		while (g_variant_iter_loop(&array_iter, "(&s&sii)",
					&info.display_name,
					&info.name,
					&info.version,
					&state)) {
			info.state = state;
			priv->plugins[i] = g_slist_append(priv->plugins[i], sf_secrets_plugin_info_copy(&info));
		}
	}
	*/

	g_task_return_boolean(task, TRUE);
	g_object_unref(task);
	g_variant_unref(response);
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

	g_dbus_proxy_call(priv->proxy,
			"getPluginInfo",
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			g_task_get_cancellable(task),
			_sf_secrets_manager_get_plugin_info_ready,
			task);
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
				g_quark_from_static_string("SfSecrets"),
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

	if (result_code != 0) {
		if (error)
			*error = g_error_new(
					g_quark_from_static_string("SfSecrets"),
					error_code, "%s", error_msg);
		res = FALSE;
	}

	g_variant_unref(result);

	return res;
}

static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
	async_initable_iface->init_async = _async_initable_init_async;
	async_initable_iface->init_finish = _async_initable_init_finish;
}

void sf_secrets_manager_get_collection(SfSecretsManager *manager,
		const gchar *plugin_name,
		const gchar *name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	g_async_initable_new_async(SF_TYPE_SECRETS_COLLECTION,
			G_PRIORITY_DEFAULT,
			cancellable,
			callback,
			user_data,
			"manager", manager,
			"plugin-name", plugin_name,
			"name", name,
			"flags", (guint)SF_SECRETS_COLLECTION_FLAGS_MODE_GET,
			NULL);
}

SfSecretsCollection *sf_secrets_manager_get_collection_finish(GAsyncResult *res,
		GError **error)
{
	GObject *src_obj = g_async_result_get_source_object(res);
	GObject *obj = g_async_initable_new_finish(G_ASYNC_INITABLE(src_obj),
			res, error);
	g_object_unref(src_obj);

	return SF_SECRETS_COLLECTION(obj);
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
	g_async_initable_new_async(SF_TYPE_SECRETS_COLLECTION,
			G_PRIORITY_DEFAULT,
			cancellable,
			callback,
			user_data,
			"manager", manager,
			"plugin-name", plugin_name,
			"encryption-plugin-name", encryption_plugin_name,
			"authentication-plugin-name", authentication_plugin_name,
			"device-unlock-semantic", unlock_semantic,
			"access-control-mode", access_control_mode,
			"name", name,
			"flags", (guint)SF_SECRETS_COLLECTION_FLAGS_MODE_CREATE,
			NULL);
}

SfSecretsCollection *sf_secrets_manager_create_collection_finish(GAsyncResult *res,
		GError **error)
{
	return sf_secrets_manager_get_collection_finish(res, error);
}

void sf_secrets_manager_ensure_collection(SfSecretsManager *manager,
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
	g_async_initable_new_async(SF_TYPE_SECRETS_COLLECTION,
			G_PRIORITY_DEFAULT,
			cancellable,
			callback,
			user_data,
			"manager", manager,
			"plugin-name", plugin_name,
			"encryption-plugin-name", encryption_plugin_name,
			"authentication-plugin-name", authentication_plugin_name,
			"device-unlock-semantic", (guint)unlock_semantic,
			"access-control-mode", (guint)access_control_mode,
			"flags", (guint)SF_SECRETS_COLLECTION_FLAGS_MODE_ENSURE,
			"name", name,
			NULL);
}

SfSecretsCollection *sf_secrets_manager_ensure_collection_finish(GAsyncResult *res,
		GError **error)
{
	return sf_secrets_manager_get_collection_finish(res, error);
}

void _sf_secrets_manager_get_interaction_mode(SfSecretsManager *manager,
		SfSecretsUserInteractionMode *mode,
		const gchar **user_interaction_service_address)
{
	SfSecretsManagerPrivate *priv = sf_secrets_manager_get_instance_private(manager);

	*mode = priv->user_interaction_mode;
	if (priv->interaction_service_address)
		*user_interaction_service_address = priv->interaction_service_address;
	else
		*user_interaction_service_address = "";
}

SfSecretsCollection *sf_secrets_manager_get_default_collection(SfSecretsManager *manager,
		const gchar *plugin_name,
		const gchar *encryption_plugin_name,
		const gchar *authentication_plugin_name,
		SfSecretsDeviceUnlockSemantic unlock_semantic,
		SfSecretsAccessControlMode access_control_mode)
{
	return g_object_new(SF_TYPE_SECRETS_COLLECTION,
			"manager", manager,
			"plugin-name", plugin_name,
			"encryption-plugin-name", encryption_plugin_name,
			"authentication-plugin-name", authentication_plugin_name,
			"device-unlock-semantic", unlock_semantic,
			"access-control-mode", access_control_mode,
			"flags", SF_SECRETS_COLLECTION_FLAGS_MODE_DEFAULT,
			NULL);
}

void _sf_secrets_manager_result_only_ready(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	GTask *task = user_data;
	GError *error;
	GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
			res, &error);

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	if (!_sf_secrets_manager_check_reply(response, &error, NULL)) {
		g_task_return_error(task, error);
		g_object_unref(task);
		g_variant_unref(response);
		return;
	}

	g_task_return_boolean(task, TRUE);
	g_object_unref(task);
}

void _sf_secrets_manager_query_lock_status_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariant *ret = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object), res, &error);
	GVariantIter iter;
	gint32 status;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	if (!_sf_secrets_manager_check_reply(ret, &error, &iter)) {
		g_task_return_error(task, error);
		g_object_unref(task);
		g_variant_unref(ret);
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
				target ?: "",
				"", "", "",
				authentication_plugin_name,
				0, "",
				g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0),
				input_type,
				echo_mode,
				priv->user_interaction_mode,
				priv->interaction_service_address ?: ""),
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
