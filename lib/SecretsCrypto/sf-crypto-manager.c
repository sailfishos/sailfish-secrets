#include "sf-crypto.h"
#include "sf-crypto-manager.h"
#include "sf-crypto-key-private.h"
#include "sf-common-private.h"

const gchar *SF_CRYPTO_DEFAULT_PLUGIN = "plugin.crypto.default";
const gchar *SF_CRYPTO_DEFAULT_STORAGE_PLUGIN = "plugin.cryptostorage.default";
const gchar *SF_CRYPTO_DEFAULT_CSPRNG_ENGINE = "default";

typedef struct SfCryptoManagerPrivate_ SfCryptoManagerPrivate;
/*
typedef enum SfCryptoManagerSignal_ {
	SIGNAL_COUNT
} SfCryptoManagerSignal;
*/

/*
static guint _sf_crypto_manager_signals[SIGNAL_COUNT];
*/

struct SfCryptoManagerPrivate_
{
	GDBusProxy *proxy;
	/*
	GSList *plugins[SF_SECRET_PLUGIN_TYPE_COUNT];
	*/
	gchar *application_id;
	gboolean user_interaction_mode_set;
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
};

G_DEFINE_TYPE_WITH_CODE(SfCryptoManager, sf_crypto_manager, G_TYPE_OBJECT,
		G_ADD_PRIVATE(SfCryptoManager)
		G_IMPLEMENT_INTERFACE(G_TYPE_ASYNC_INITABLE, _async_initable_iface_init))

static void sf_crypto_manager_init(SfCryptoManager *manager)
{
	(void)manager;
}

static void _sf_crypto_manager_finalize(GObject *object)
{
	SfCryptoManager *manager = SF_CRYPTO_MANAGER(object);
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	/*
	int i;
	*/

	if (priv->proxy)
		g_object_unref(priv->proxy);

	if (priv->application_id)
		g_free(priv->application_id);

	/*
	for (i = 0; i < SF_SECRET_PLUGIN_TYPE_COUNT; i++) {
		g_slist_foreach(priv->plugins[i], (GFunc)sf_crypto_plugin_info_free, NULL);
		g_slist_free(priv->plugins[i]);
	}
	*/
}

static void _sf_crypto_manager_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *spec)
{
	SfCryptoManager *manager = SF_CRYPTO_MANAGER(object);
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);

	(void)spec;

	switch (property_id) {
		case PROP_APPLICATION_ID:
			g_value_set_string(value, priv->application_id);
			break;
		default:
			g_warning("Unknown property %u", property_id);
			break;
	}
}

static void _sf_crypto_manager_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *spec)
{
	SfCryptoManager *manager = SF_CRYPTO_MANAGER(object);
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);

	(void)spec;

	switch (property_id) {
		case PROP_APPLICATION_ID:
			if (priv->application_id)
				g_free(priv->application_id);
			priv->application_id = g_value_dup_string(value);
			break;
		default:
			g_warning("Unknown property %u", property_id);
			break;
	}
}

static void sf_crypto_manager_class_init(SfCryptoManagerClass *manager_class)
{
	G_OBJECT_CLASS(manager_class)->finalize = _sf_crypto_manager_finalize;
	G_OBJECT_CLASS(manager_class)->set_property = _sf_crypto_manager_set_property;
	G_OBJECT_CLASS(manager_class)->get_property = _sf_crypto_manager_get_property;

	g_object_class_install_property(G_OBJECT_CLASS(manager_class),
			PROP_APPLICATION_ID,
			g_param_spec_string("application-id",
				"application-id",
				"Application ID",
				NULL,
				G_PARAM_READWRITE |
				G_PARAM_STATIC_STRINGS));
}

static GVariant *_sf_variant_new_variant_map_or_empty(GHashTable *hash_table)
{
	GVariantDict var_dict;

	g_variant_dict_init(&var_dict, NULL);

	if (hash_table) {
		GHashTableIter ht_iter;
		gpointer key;
		gpointer value;
		g_hash_table_iter_init(&ht_iter, hash_table);
		while (g_hash_table_iter_next(&ht_iter, &key, &value))
			g_variant_dict_insert_value(&var_dict, key, value);
	}

	return g_variant_dict_end(&var_dict);
}

#define SF_KPG_VARIANT_STRING "(ia{sv}a{sv})"

static GVariant *_sf_variant_new_kpg_or_empty(SfCryptoKpgParams *params) {
	if (!params)
		return g_variant_new("(i@a{sv}@a{sv})",
				(gint32)SF_CRYPTO_KEY_PAIR_TYPE_UNKNOWN,
				g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0),
				g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0));
	return g_variant_new("(i@a{sv}@a{sv})",
			(gint32)params->type,
			_sf_variant_new_variant_map_or_empty(params->custom_params),
			_sf_variant_new_variant_map_or_empty(params->type_params));
}

#define SF_SKDF_VARIANT_STRING "(ayay(i)(i)(i)(i)xiiia{sv})"
static GVariant *_sf_variant_new_skdf_or_empty(SfCryptoSkdfParams *params)
{
	if (!params)
		return g_variant_new("(@ay@ay(i)(i)(i)(i)xiiia@a{sv}",
				g_variant_new_array(G_VARIANT_TYPE_BYTE, NULL, 0),
				g_variant_new_array(G_VARIANT_TYPE_BYTE, NULL, 0),
				SF_CRYPTO_KDF_UNKNOWN,
				SF_CRYPTO_MAC_UNKNOWN,
				SF_CRYPTO_ALGORITHM_UNKNOWN,
				SF_CRYPTO_DIGEST_UNKNOWN,
				(gint64)0, (gint32)0, (gint32)0,
				g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0));
	return g_variant_new("(@ay@ay(i)(i)(i)(i)xiiia@a{sv}",
			_sf_variant_new_bytes_or_empty(params->input_data),
			_sf_variant_new_bytes_or_empty(params->salt),
			(gint32)params->function,
			(gint32)params->mac,
			(gint32)params->algorithm,
			(gint32)params->digest,
			(gint64)params->memory_size,
			(gint32)params->iterations,
			(gint32)params->key_size,
			_sf_variant_new_variant_map_or_empty(params->custom_params));
}

SfCryptoManager *sf_crypto_manager_new_finish(GAsyncResult *res,
		GError **error)
{
	GObject *src_obj = g_async_result_get_source_object(res);
	GObject *obj = g_async_initable_new_finish(G_ASYNC_INITABLE(src_obj),
			res, error);
	g_object_unref(src_obj);

	return SF_CRYPTO_MANAGER(obj);
}

void sf_crypto_manager_new(GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	g_async_initable_new_async(SF_TYPE_CRYPTO_MANAGER,
			G_PRIORITY_DEFAULT,
			cancellable,
			callback,
			user_data,
			NULL);
}

gboolean _sf_crypto_manager_check_reply(GVariant *response, GError **error, GVariantIter *iter)
{
	GVariantIter i;
	GVariant *result;
	gint32 result_code;
	gint32 error_code;
	gint32 storage_error_code;
	const gchar *error_msg;
	gboolean res = TRUE;

	if (!iter)
		iter = &i;

	g_variant_iter_init(iter, response);
	result = g_variant_iter_next_value(iter);
	g_variant_get(result, "(iii&s)", &result_code, &error_code, &storage_error_code, &error_msg);

	if (result_code != SF_CRYPTO_RESULT_SUCCEEDED) {
		if (error)
			*error = g_error_new(
					g_quark_from_static_string("SfCrypto"),
					error_code, "%s", error_msg);
		res = FALSE;
	}

	g_variant_unref(result);

	return res;
}

static GVariant *_sf_crypto_manager_dbus_call_finish(GObject *source_object,
		GAsyncResult *res,
		GError **error,
		GVariantIter *iter)
{
	GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
			res, error);

	if (!response)
		return response;

	if (!_sf_crypto_manager_check_reply(response, error, iter)) {
		g_variant_unref(response);
		return NULL;
	}

	return response;
}

static void _sf_crypto_manager_get_plugin_info_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariantIter iter;
	GVariant *response = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	g_task_set_task_data(task, response, (GDestroyNotify)g_variant_unref);
	g_task_return_pointer(task, g_variant_iter_copy(&iter), (GDestroyNotify)g_variant_iter_free);
	g_object_unref(task);
}

void sf_crypto_manager_get_plugin_info(SfCryptoManager *manager,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	GTask *task = g_task_new(manager, cancellable, callback, user_data);
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);

	g_dbus_proxy_call(priv->proxy,
			"getPluginInfo",
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			g_task_get_cancellable(task),
			_sf_crypto_manager_get_plugin_info_ready,
			task);
}

gboolean sf_crypto_manager_get_plugin_info_finish(GAsyncResult *res,
		GSList **crypto_plugins,
		GSList **storage_plugins,
		GError **error)
{
	gsize i;
	GSList **plugin_lists[] = {
		crypto_plugins,
		storage_plugins,
	};
	GVariantIter *iter = g_task_propagate_pointer(G_TASK(res), error);

	if (!iter)
		return FALSE;

	for (i = 0; i < G_N_ELEMENTS(plugin_lists); i++) {
		GVariant *array = g_variant_iter_next_value(iter);
		GVariantIter array_iter;
		SfCryptoPluginInfo info;
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
			*plugin_lists[i] = g_slist_append(*plugin_lists[i], sf_crypto_plugin_info_copy(&info));
		}
		g_variant_unref(array);
	}

	g_variant_iter_free(iter);

	return TRUE;
}

static void _sf_crypto_manager_proxy_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	SfCryptoManager *secrets = g_task_get_source_object(task);
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(secrets);
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

void _sf_crypto_manager_connection_ready(GObject *source_object,
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
			"/Sailfish/Crypto",
			"org.sailfishos.secrets",
			g_task_get_cancellable(task),
			_sf_crypto_manager_proxy_ready,
			task);
}

void _sf_crypto_manager_discovery_ready(GObject *source_object,
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
				g_quark_from_static_string("SfCrypto"),
				SF_CRYPTO_ERROR_DAEMON, "Daemon sent a reply we didn't understand");
		g_object_unref(task);
		return;
	}

	g_task_set_task_data(task, NULL, NULL);
	g_dbus_connection_new_for_address(address,
			G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
			NULL,
			g_task_get_cancellable(task),
			_sf_crypto_manager_connection_ready,
			task);
	g_variant_unref(response);
}

void _sf_crypto_manager_discovery_proxy_ready(GObject *source_object,
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
			_sf_crypto_manager_discovery_ready,
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
			"org.sailfishos.crypto.daemon.discovery",
			"/Sailfish/Crypto/Discovery",
			"org.sailfishos.crypto.daemon.discovery",
			cancellable,
			_sf_crypto_manager_discovery_proxy_ready,
			task);
}

static gboolean _async_initable_init_finish (GAsyncInitable *initable,
		GAsyncResult *res,
		GError **error)
{
	(void)initable;
	return g_task_propagate_boolean(G_TASK(res), error);
}

GDBusProxy *_sf_crypto_manager_get_dbus_proxy(SfCryptoManager *manager)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	return g_object_ref(priv->proxy);
}

static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
	async_initable_iface->init_async = _async_initable_init_async;
	async_initable_iface->init_finish = _async_initable_init_finish;
}

static void _sf_crypto_manager_result_bytearray_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariantIter iter;
	GVariant *ret = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);
	GVariant *digest;
	const guchar *digest_data;
	gsize digest_len;
	GBytes *digest_bytes;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	g_variant_iter_next(&iter, "@ay", &digest);
	digest_data = g_variant_get_fixed_array(digest, &digest_len, sizeof(guchar));
	digest_bytes = g_bytes_new(digest_data, digest_len);

	g_variant_unref(digest);
	g_variant_unref(ret);
	g_task_return_pointer(task, digest_bytes, (GDestroyNotify)g_bytes_unref);
	g_object_unref(task);
}

static void _sf_crypto_manager_result_key_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariantIter iter;
	GVariant *response = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);
	GVariant *key;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	key = g_variant_iter_next_value(&iter);
	g_task_return_pointer(task, _sf_crypto_key_from_variant(key), g_object_unref);
	g_object_unref(task);
	g_variant_unref(key);
	g_variant_unref(response);
}

static void _sf_crypto_manager_result_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariant *ret = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, NULL);

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	g_variant_unref(ret);
	g_task_return_boolean(task, TRUE);
	g_object_unref(task);
}

static void _sf_crypto_manager_generate_random_data_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_bytearray_ready(source_object, res, user_data);
}

void sf_crypto_manager_generate_random_data(SfCryptoManager *manager,
		guint64 amount,
		const gchar *engine_name,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"generateRandomData",
			g_variant_new("(ts@a{sv}s)",
				amount,
				engine_name,
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_generate_random_data_ready,
			task);
}

GBytes *sf_crypto_manager_generate_random_data_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}

static void _sf_crypto_manager_generate_initialization_vector_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_bytearray_ready(source_object, res, user_data);
}

void sf_crypto_manager_generate_initialization_vector(SfCryptoManager *manager,
		SfCryptoAlgorithm algorithm,
		SfCryptoBlockMode block_mode,
		gint key_size,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"generateInitializationVector",
			g_variant_new("((i)(i)ia{sv}s)",
				algorithm,
				block_mode,
				key_size,
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_generate_initialization_vector_ready,
			task);
}

GBytes *sf_crypto_manager_generate_initialization_vector_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}

static void _sf_crypto_manager_generate_key_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_key_ready(source_object, res, user_data);
}

void sf_crypto_manager_generate_key(SfCryptoManager *manager,
		SfCryptoKey *key_template,
		SfCryptoKpgParams *kpg_params,
		SfCryptoSkdfParams *skdf_params,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"generateKey",
			g_variant_new("(@" SF_CRYPTO_KEY_VARIANT_STRING
				"@" SF_KPG_VARIANT_STRING
				"@" SF_SKDF_VARIANT_STRING
				"@a{sv}s",
				_sf_crypto_key_to_variant(key_template),
				_sf_variant_new_kpg_or_empty(kpg_params),
				_sf_variant_new_skdf_or_empty(skdf_params),
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_generate_key_ready,
			task);
}

SfCryptoKey *sf_crypto_manager_generate_key_finish(GAsyncResult *res, GError **error)
{
	return g_object_ref_sink(g_task_propagate_pointer(G_TASK(res), error));
}

static void _sf_crypto_manager_generate_stored_key_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_key_ready(source_object, res, user_data);
}

void sf_crypto_manager_generate_stored_key(SfCryptoManager *manager,
		SfCryptoKey *key_template,
		SfCryptoKpgParams *kpg_params,
		SfCryptoSkdfParams *skdf_params,
		const gchar *authentication_plugin,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"generateStoredKey",
			g_variant_new("(@" SF_CRYPTO_KEY_VARIANT_STRING
				"@" SF_KPG_VARIANT_STRING
				"@" SF_SKDF_VARIANT_STRING
				"(ssss(i)s@a{is}(i)(i))"
				"a{sv}s",

				_sf_crypto_key_to_variant(key_template),
				_sf_variant_new_kpg_or_empty(kpg_params),
				_sf_variant_new_skdf_or_empty(skdf_params),

				"", "", "", "", 0, authentication_plugin,
				g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0),
				input_type, echo_mode,

				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_generate_stored_key_ready,
			task);
}

SfCryptoKey *sf_crypto_manager_generate_stored_key_finish(GAsyncResult *res, GError **error)
{
	return g_object_ref_sink(g_task_propagate_pointer(G_TASK(res), error));
}

static void _sf_crypto_manager_import_key_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_key_ready(source_object, res, user_data);
}

void sf_crypto_manager_import_key(SfCryptoManager *manager,
		GBytes *data,
		const gchar *authentication_plugin,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"importKey",
			g_variant_new("(@ay"
				"(ssss(i)s@a{is}(i)(i))"
				"@a{sv}s)",
				_sf_variant_new_bytes_or_empty(data),
				"", "", "", "", 0, authentication_plugin,
				g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0),
				input_type, echo_mode,
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_import_key_ready,
			task);
}

SfCryptoKey *sf_crypto_manager_import_key_finish(GAsyncResult *res, GError **error)
{
	return g_object_ref_sink(g_task_propagate_pointer(G_TASK(res), error));
}

static void _sf_crypto_manager_import_stored_key_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_key_ready(source_object, res, user_data);
}

void sf_crypto_manager_import_stored_key(SfCryptoManager *manager,
		GBytes *data,
		SfCryptoKey *key_template,
		const gchar *authentication_plugin,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_object_ref_sink(key_template);

	g_dbus_proxy_call(priv->proxy,
			"importStoredKey",
			g_variant_new("(@ay@" SF_CRYPTO_KEY_VARIANT_STRING "(ssss(i)s@a{is}(i)(i))@a{sv}s)",
				_sf_variant_new_bytes_or_empty(data),
				_sf_crypto_key_to_variant(key_template),
				"", "", "", "", 0, authentication_plugin,
				g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0),
				input_type, echo_mode,
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_import_stored_key_ready,
			task);

	g_object_unref(key_template);
}

SfCryptoKey *sf_crypto_manager_import_stored_key_finish(GAsyncResult *res, GError **error)
{
	return g_object_ref_sink(g_task_propagate_pointer(G_TASK(res), error));
}

static void _sf_crypto_manager_seed_random_data_generator_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_ready(source_object, res, user_data);
}

void sf_crypto_manager_seed_random_data_generator(SfCryptoManager *manager,
		GBytes *seed_data,
		gdouble entropy_estimate,
		const gchar *engine_name,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"seedRandomDataGenerator",
			g_variant_new("(@ayds@a{sv}s)",
				_sf_variant_new_bytes_or_empty(seed_data),
				entropy_estimate,
				engine_name,
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_seed_random_data_generator_ready,
			task);
}

gboolean sf_crypto_manager_seed_random_data_generator_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_crypto_manager_calculate_digest_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_bytearray_ready(source_object, res, user_data);
}

void sf_crypto_manager_calculate_digest(SfCryptoManager *manager,
		GBytes *data,
		SfCryptoSignaturePadding padding,
		SfCryptoDigest digest,
		GHashTable *custom_params, /* char * => GVariant */
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"calculateDigest",
			g_variant_new("(@ay(i)(i)a{sv}s)",
				_sf_variant_new_bytes_or_empty(data),
				padding,
				digest,
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_calculate_digest_ready,
			task);
}

GBytes *sf_crypto_manager_calculate_digest_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}

static void _sf_crypto_manager_stored_key_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_key_ready(source_object, res, user_data);
}

void sf_crypto_manager_stored_key(SfCryptoManager *manager,
		const gchar *name,
		const gchar *collection_name,
		const gchar *plugin_name,
		SfCryptoKeyConstraint components,
		GHashTable *custom_params,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"storedKey",
			g_variant_new("((sss)(i)@a{sv})",
				name,
				collection_name,
				plugin_name,
				(gint32)components,
				_sf_variant_new_variant_map_or_empty(custom_params)),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_stored_key_ready,
			task);
}

SfCryptoKey *sf_crypto_manager_stored_key_finish(GAsyncResult *res, GError **error)
{
	return g_object_ref_sink(g_task_propagate_pointer(G_TASK(res), error));
}

static void _sf_crypto_manager_delete_stored_key_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_ready(source_object, res, user_data);
}


void sf_crypto_manager_delete_stored_key(SfCryptoManager *manager,
		const gchar *name,
		const gchar *collection_name,
		const gchar *plugin_name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"deleteStoredKey",
			g_variant_new("((sss)(i)@a{sv})",
				name,
				collection_name,
				plugin_name),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_delete_stored_key_ready,
			task);
}

gboolean sf_crypto_manager_delete_stored_key_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_crypto_manager_stored_key_names_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariantIter iter;
	GVariant *response = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);
	GArray *key_names;
	GVariant *keys;
	GVariantIter key_iter;
	gchar *key_name;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	key_names = g_array_new(TRUE, FALSE, sizeof(gchar *));
	keys = g_variant_iter_next_value(&iter);

	g_variant_iter_init(&key_iter, keys);
	while (g_variant_iter_loop(&key_iter, "(s&s&s)",
				&key_name,
				NULL,
				NULL))
		g_array_append_val(key_names, key_name);
	g_variant_unref(keys);
	g_variant_unref(response);

	g_task_return_pointer(task, g_array_free(key_names, FALSE), (GDestroyNotify)g_strfreev);
	g_object_unref(task);
}

void sf_crypto_manager_stored_key_names(SfCryptoManager *manager,
		const gchar *plugin_name,
		const gchar *collection_name,
		GHashTable *custom_params,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"storedKeyIdentifiers",
			g_variant_new("(ss@a{sv})",
				plugin_name,
				collection_name,
				_sf_variant_new_variant_map_or_empty(custom_params)),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_stored_key_names_ready,
			task);
}

gchar **sf_crypto_manager_stored_key_names_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}

static void _sf_crypto_manager_sign_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_bytearray_ready(source_object, res, user_data);
}

void sf_crypto_manager_sign(SfCryptoManager *manager,
		GBytes *data,
		SfCryptoKey *key,
		SfCryptoSignaturePadding padding,
		SfCryptoDigest digest,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"sign",
			g_variant_new("(@ay@" SF_CRYPTO_KEY_VARIANT_STRING "(i)(i)@a{sv}s)",
				_sf_variant_new_bytes_or_empty(data),
				_sf_crypto_key_to_variant(key),
				padding,
				digest,
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_sign_ready,
			task);
}

GBytes *sf_crypto_manager_sign_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}

static void _sf_crypto_manager_verify_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariantIter iter;
	GVariant *ret = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);
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

void sf_crypto_manager_verify(SfCryptoManager *manager,
		GBytes *signature,
		GBytes *data,
		SfCryptoKey *key,
		SfCryptoSignaturePadding padding,
		SfCryptoDigest digest,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"verify",
			g_variant_new("(@ay@ay@" SF_CRYPTO_KEY_VARIANT_STRING "(i)(i)@a{sv}s)",
				_sf_variant_new_bytes_or_empty(signature),
				_sf_variant_new_bytes_or_empty(data),
				_sf_crypto_key_to_variant(key),
				padding,
				digest,
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_verify_ready,
			task);
}

SfCryptoVerificationStatus sf_crypto_manager_verify_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_int(G_TASK(res), error);
}

static void _sf_crypto_manager_encrypt_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariantIter iter;
	GVariant *ret = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);
	GVariant *enc_data;
	GVariant *tag;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	enc_data = g_variant_iter_next_value(&iter);
	tag = g_variant_iter_next_value(&iter);

	g_task_set_task_data(task, _sf_bytes_new_from_variant_or_null(tag), (GDestroyNotify)g_bytes_unref);
	g_task_return_pointer(task, _sf_bytes_new_from_variant_or_null(enc_data), (GDestroyNotify)g_bytes_unref);
	g_object_unref(task);

	g_variant_unref(tag);
	g_variant_unref(enc_data);
	g_variant_unref(ret);
}

void sf_crypto_manager_encrypt(SfCryptoManager *manager,
		GBytes *data,
		GBytes *iv,
		SfCryptoKey *key,
		SfCryptoBlockMode block_mode,
		SfCryptoEncryptionPadding padding,
		GBytes *authentication_data,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"encrypt",
			g_variant_new("(@ay@ay@" SF_CRYPTO_KEY_VARIANT_STRING "(i)(i)@ay@a{sv}s",
				_sf_variant_new_bytes_or_empty(data),
				_sf_variant_new_bytes_or_empty(iv),
				_sf_crypto_key_to_variant(key),
				block_mode,
				padding,
				_sf_variant_new_bytes_or_empty(authentication_data),
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_encrypt_ready,
			task);
}

GBytes *sf_crypto_manager_encrypt_finish(GAsyncResult *res, GBytes **tag, GError **error)
{
	GError *err;
	GBytes *rv = g_task_propagate_pointer(G_TASK(res), &err);

	if (err) {
		if (error)
			*error = err;
		else
			g_error_free(err);

		return rv;

	}

	if (tag)
		*tag = g_object_ref(g_task_get_task_data(G_TASK(res)));

	return rv;
}

static void _sf_crypto_manager_decrypt_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariantIter iter;
	GVariant *ret = _sf_crypto_manager_dbus_call_finish(source_object, res, &error, &iter);
	GVariant *dec_data;
	gint32 status;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	dec_data = g_variant_iter_next_value(&iter);
	g_variant_iter_next(&iter, "(i)", &status);

	g_task_set_task_data(task, GINT_TO_POINTER(status), NULL);
	g_task_return_pointer(task, _sf_bytes_new_from_variant_or_null(dec_data), (GDestroyNotify)g_bytes_unref);
	g_object_unref(task);

	g_variant_unref(dec_data);
	g_variant_unref(ret);
}

void sf_crypto_manager_decrypt(SfCryptoManager *manager,
		GBytes *data,
		GBytes *iv,
		SfCryptoKey *key,
		SfCryptoBlockMode block_mode,
		SfCryptoEncryptionPadding padding,
		GBytes *authentication_data,
		GBytes *authentication_tag,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"decrypt",
			g_variant_new("(@ay@ay@" SF_CRYPTO_KEY_VARIANT_STRING "(i)(i)@ay@a{sv}s",
				_sf_variant_new_bytes_or_empty(data),
				_sf_variant_new_bytes_or_empty(iv),
				_sf_crypto_key_to_variant(key),
				block_mode,
				padding,
				_sf_variant_new_bytes_or_empty(authentication_data),
				_sf_variant_new_bytes_or_empty(authentication_tag),
				_sf_variant_new_variant_map_or_empty(custom_params),
				crypto_provider),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_decrypt_ready,
			task);
}

GBytes *sf_crypto_manager_decrypt_finish(GAsyncResult *res, SfCryptoVerificationStatus *status, GError **error)
{
	GError *err;
	GBytes *rv = g_task_propagate_pointer(G_TASK(res), &err);

	if (err) {
		if (error)
			*error = err;
		else
			g_error_free(err);

		return rv;

	}

	if (status)
		*status = GPOINTER_TO_INT(g_task_get_task_data(G_TASK(res)));

	return rv;
}

/*
void _sf_crypto_manager_query_lock_status_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariant *ret = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object), res, &error);
	GVariantIter iter;
	gint status;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	if (!_sf_crypto_manager_check_reply(ret, &error, &iter)) {
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

void sf_crypto_manager_query_lock_status(SfCryptoManager *manager,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			"queryLockStatus",
			g_variant_new("((i)s)",
				(gint)target_type,
				target),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_query_lock_status_ready,
			task);
}

SfCryptoLockStatus sf_crypto_manager_query_lock_status_finish(GAsyncResult *res,
		GError **error)
{
	return g_task_propagate_int(G_TASK(res), error);
}

static void _sf_crypto_manager_lock_code_request_reply(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_crypto_manager_result_only_ready(source_object, res, user_data);
}

static void _sf_crypto_manager_lock_code_request(SfCryptoManager *manager,
		const gchar *method,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfCryptoManagerPrivate *priv = sf_crypto_manager_get_instance_private(manager);
	GTask *task = g_task_new(manager, cancellable, callback, user_data);

	g_dbus_proxy_call(priv->proxy,
			method,
			g_variant_new("((i)s(ssss(i)s@a{is}(i)(i))(i)s)",
				target_type,
				target ?: "",
				"", "", "",
				authentication_plugin_name,
				0, "",
				g_variant_new_parsed("@a{is} {}"),
				input_type,
				echo_mode,
				priv->user_interaction_mode,
				priv->interaction_service_address ?: ""),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_crypto_manager_lock_code_request_reply,
			task);
}

void sf_crypto_manager_modify_lock_code(SfCryptoManager *manager,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	_sf_crypto_manager_lock_code_request(manager,
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

gboolean sf_crypto_manager_modify_lock_code_finish(GAsyncResult *res,
		GError **error)
{
	return g_task_propagate_boolean(G_TASK(res), error);
}

void sf_crypto_manager_provide_lock_code(SfCryptoManager *manager,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	_sf_crypto_manager_lock_code_request(manager,
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

gboolean sf_crypto_manager_provide_lock_code_finish(GAsyncResult *res,
		GError **error)
{
	return g_task_propagate_boolean(G_TASK(res), error);
}

void sf_crypto_manager_forget_lock_code(SfCryptoManager *manager,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	_sf_crypto_manager_lock_code_request(manager,
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

gboolean sf_crypto_manager_forget_lock_code_finish(GAsyncResult *res,
		GError **error)
{
	return g_task_propagate_boolean(G_TASK(res), error);
}
*/
