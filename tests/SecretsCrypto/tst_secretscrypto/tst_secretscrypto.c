#include <SecretsCrypto/sf-secrets-manager.h>
#include <SecretsCrypto/sf-crypto-manager.h>
#include <glib.h>

#include <string.h>

#define SECRETS_PLUGIN_STORAGE_TEST "org.sailfishos.secrets.plugin.storage.sqlite.test"
#define SECRETS_PLUGIN_ENCRYPTION_TEST "org.sailfishos.secrets.plugin.encryption.openssl.test"
#define CRYPTO_PLUGIN_TEST "org.sailfishos.crypto.plugin.crypto.openssl.test"

typedef struct SfSecretsFixture_ {
	GMainLoop *loop;
	GError *error;
	SfSecretsManager *manager;
	GAsyncResult *test_res;
} SfSecretsFixture;

typedef struct SfCryptoFixture_ {
	GMainLoop *loop;
	GError *error;
	SfCryptoManager *manager;
	GAsyncResult *test_res;
} SfCryptoFixture;

static void _tst_secret_ref_res_and_quit(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	SfSecretsFixture *fixture = user_data;

	(void)source_object;

	fixture->test_res = g_object_ref(res);
	g_test_queue_unref(fixture->test_res);
	g_main_loop_quit(fixture->loop);
}

static void tst_secret_create_manager(SfSecretsFixture *fixture,
		gconstpointer data)
{
	(void)data;
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->manager);
}

static void tst_secret_get_plugin_info(SfSecretsFixture *fixture,
		gconstpointer data)
{
	GSList *plgns[] = { (GSList *)0xdeadbeef, NULL, NULL, NULL };
	gsize i;

	(void)data;

	if (!fixture->manager) {
		g_test_skip("No manager");
		return;
	}

	sf_secrets_manager_get_plugin_info(fixture->manager,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_get_plugin_info_finish(
			fixture->test_res,
			&plgns[0],
			&plgns[1],
			&plgns[2],
			&plgns[3],
			&fixture->error);
	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	for (i = 0; i < G_N_ELEMENTS(plgns); i++) {
		while (plgns[i]) {
			g_debug("Found plugin: %s", ((SfSecretsPluginInfo *)plgns[i]->data)->name);
			sf_secrets_plugin_info_free(plgns[i]->data);
			plgns[i] = g_slist_delete_link(plgns[i], plgns[i]);
		}
	}
}

static void tst_secret_get_health_info(SfSecretsFixture *fixture,
		gconstpointer data)
{
	SfSecretsHealth salth;
	SfSecretsHealth mlockh;
	gboolean is_healthy;

	(void)data;

	if (!fixture->manager) {
		g_test_skip("No manager");
		return;
	}
	sf_secrets_manager_get_health_info(fixture->manager, NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_get_health_info_finish(fixture->test_res,
			&is_healthy,
			&salth,
			&mlockh,
			&fixture->error);
	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_debug("Healthy: %d", is_healthy);
}

static void tst_secret_collection_names(SfSecretsFixture *fixture,
		gconstpointer data)
{
	gchar **collections;
	gsize i;

	(void)data;

	if (!fixture->manager) {
		g_test_skip("No manager");
		return;
	}
	sf_secrets_manager_collection_names(fixture->manager,
			SECRETS_PLUGIN_STORAGE_TEST,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	collections = sf_secrets_manager_collection_names_finish(fixture->test_res,
			&fixture->error);
	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	for (i = 0; collections[i]; i++)
		g_debug("Found collection: %s", collections[i]);
	g_strfreev(collections);
}

static void tst_secret_create_delete_collection(SfSecretsFixture *fixture,
		gconstpointer data)
{
	(void)data;

	if (!fixture->manager) {
		g_test_skip("No manager");
		return;
	}
	sf_secrets_manager_create_collection(
			fixture->manager,
			SECRETS_PLUGIN_STORAGE_TEST,
			SECRETS_PLUGIN_ENCRYPTION_TEST,
			NULL,
			"tst_capi_collection",
			SF_SECRETS_DEVICE_UNLOCK_SEMANTIC_KEEP_UNLOCKED,
			SF_SECRETS_ACCESS_CONTROL_MODE_OWNER_ONLY,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_create_collection_finish(fixture->test_res, &fixture->error);

	if (fixture->error &&
			fixture->error->code == SF_SECRETS_ERROR_COLLECTION_ALREADY_EXISTS) {
		g_debug("Collection already exists, deleting it anyway");
		g_error_free(fixture->error);
		fixture->error = NULL;
	}
	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	sf_secrets_manager_delete_collection(
			fixture->manager,
			SECRETS_PLUGIN_STORAGE_TEST,
			"tst_capi_collection",
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_delete_collection_finish(fixture->test_res,
			&fixture->error);
	g_assert_no_error(fixture->error);
}

static void tst_secret_set_get_collection_secret(SfSecretsFixture *fixture,
		gconstpointer data)
{
	SfSecretsSecret *secret;
	GBytes *secret_data;
	gint8 buffer[1024];
	gsize i;

	(void)data;

	if (!fixture->manager) {
		g_test_skip("No manager");
		return;
	}

	for (i = 0; i < G_N_ELEMENTS(buffer); i++)
		buffer[i] = g_test_rand_int_range(0, G_MAXUINT8);

	sf_secrets_manager_create_collection(
			fixture->manager,
			SECRETS_PLUGIN_STORAGE_TEST,
			SECRETS_PLUGIN_ENCRYPTION_TEST,
			NULL,
			"tst_capi_collection",
			SF_SECRETS_DEVICE_UNLOCK_SEMANTIC_KEEP_UNLOCKED,
			SF_SECRETS_ACCESS_CONTROL_MODE_OWNER_ONLY,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_create_collection_finish(fixture->test_res, &fixture->error);

	if (fixture->error &&
			fixture->error->code == SF_SECRETS_ERROR_COLLECTION_ALREADY_EXISTS) {
		g_test_skip("Collection already exists, skipping");
		return;
	}
	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	secret_data = g_bytes_new_static(buffer, sizeof(buffer));
	sf_secrets_manager_set_secret(fixture->manager,
			g_object_new(SF_TYPE_SECRETS_SECRET,
				"name", "tst_capi_secret",
				"collection-name", "tst_capi_collection",
				"plugin-name", SECRETS_PLUGIN_STORAGE_TEST,
				"data", secret_data,
				NULL),
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_bytes_unref(secret_data);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_set_secret_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	sf_secrets_manager_get_secret(fixture->manager,
			"tst_capi_secret",
			"tst_capi_collection",
			SECRETS_PLUGIN_STORAGE_TEST,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	secret = sf_secrets_manager_get_secret_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_object_get(secret,
			"data", &secret_data,
			NULL);

	g_assert_cmpmem(g_bytes_get_data(secret_data, NULL), g_bytes_get_size(secret_data),
			buffer, sizeof(buffer));

	g_bytes_unref(secret_data);

	if (g_test_failed())
		return;

	sf_secrets_manager_delete_secret(fixture->manager,
			secret,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_object_unref(secret);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_delete_secret_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	sf_secrets_manager_delete_collection(
			fixture->manager,
			SECRETS_PLUGIN_STORAGE_TEST,
			"tst_capi_collection",
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_delete_collection_finish(fixture->test_res,
			&fixture->error);
	g_assert_no_error(fixture->error);
}

static void tst_secret_set_find_delete_collection_secret(SfSecretsFixture *fixture,
		gconstpointer data)
{
	SfSecretsSecret *secret;
	GBytes *secret_data;
	gint8 buffer[1024];
	gsize i;
	gchar **secret_names;

	(void)data;

	if (!fixture->manager) {
		g_test_skip("No manager");
		return;
	}

	for (i = 0; i < G_N_ELEMENTS(buffer); i++)
		buffer[i] = g_test_rand_int_range(0, G_MAXUINT8);

	sf_secrets_manager_create_collection(
			fixture->manager,
			SECRETS_PLUGIN_STORAGE_TEST,
			SECRETS_PLUGIN_ENCRYPTION_TEST,
			NULL,
			"tst_capi_collection",
			SF_SECRETS_DEVICE_UNLOCK_SEMANTIC_KEEP_UNLOCKED,
			SF_SECRETS_ACCESS_CONTROL_MODE_OWNER_ONLY,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_create_collection_finish(fixture->test_res, &fixture->error);

	if (fixture->error &&
			fixture->error->code == SF_SECRETS_ERROR_COLLECTION_ALREADY_EXISTS) {
		g_test_skip("Collection already exists, skipping");
		return;
	}
	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	secret_data = g_bytes_new_static(buffer, sizeof(buffer));

	secret = g_object_ref_sink(g_object_new(SF_TYPE_SECRETS_SECRET,
				"name", "tst_capi_secret",
				"collection-name", "tst_capi_collection",
				"plugin-name", SECRETS_PLUGIN_STORAGE_TEST,
				"data", secret_data,
				NULL));

	sf_secrets_secret_set_filter_field(secret, "tst_capi_field", "tst_capi_value");

	sf_secrets_manager_set_secret(fixture->manager,
			secret,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_bytes_unref(secret_data);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_set_secret_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	sf_secrets_manager_find_secrets(fixture->manager,
			"tst_capi_collection",
			SECRETS_PLUGIN_STORAGE_TEST,
			SF_SECRETS_FILTER_OPERATOR_OR,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture,
			"tst_capi_field", "tst_capi_value",
			NULL);
	g_main_loop_run(fixture->loop);

	secret_names = sf_secrets_manager_find_secrets_finish(fixture->test_res, &fixture->error);
	g_test_queue_destroy((GDestroyNotify)g_strfreev, secret_names);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_assert_cmpint(g_strv_length(secret_names), ==, 1);
	if (!g_test_failed())
		g_assert_cmpstr(secret_names[0], ==, "tst_capi_secret");

	if (g_test_failed())
		return;

	sf_secrets_manager_delete_secret(fixture->manager,
			secret,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_object_unref(secret);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_delete_secret_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	sf_secrets_manager_delete_collection(
			fixture->manager,
			SECRETS_PLUGIN_STORAGE_TEST,
			"tst_capi_collection",
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_delete_collection_finish(fixture->test_res,
			&fixture->error);
	g_assert_no_error(fixture->error);
}

static void tst_secret_set_get_standalone_secret(SfSecretsFixture *fixture,
		gconstpointer data)
{
	SfSecretsSecret *secret;
	GBytes *secret_data;
	gint8 buffer[1024];
	gsize i;

	(void)data;

	if (!fixture->manager) {
		g_test_skip("No manager");
		return;
	}

	for (i = 0; i < G_N_ELEMENTS(buffer); i++)
		buffer[i] = g_test_rand_int_range(0, G_MAXUINT8);

	secret_data = g_bytes_new_static(buffer, sizeof(buffer));
	sf_secrets_manager_set_secret_standalone(fixture->manager,
			g_object_new(SF_TYPE_SECRETS_SECRET,
				"name", "tst_capi_secret",
				"plugin-name", SECRETS_PLUGIN_STORAGE_TEST,
				"data", secret_data,
				NULL),
			SECRETS_PLUGIN_ENCRYPTION_TEST,
			NULL,
			SF_SECRETS_DEVICE_UNLOCK_SEMANTIC_KEEP_UNLOCKED,
			SF_SECRETS_ACCESS_CONTROL_MODE_OWNER_ONLY,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_bytes_unref(secret_data);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_set_secret_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	sf_secrets_manager_get_secret(fixture->manager,
			"tst_capi_secret",
			NULL,
			SECRETS_PLUGIN_STORAGE_TEST,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	secret = sf_secrets_manager_get_secret_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_object_get(secret,
			"data", &secret_data,
			NULL);

	g_assert_cmpmem(g_bytes_get_data(secret_data, NULL), g_bytes_get_size(secret_data),
			buffer, sizeof(buffer));

	g_bytes_unref(secret_data);

	if (g_test_failed())
		return;

	sf_secrets_manager_delete_secret(fixture->manager,
			secret,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_object_unref(secret);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_delete_secret_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;
}

static void _tst_crypto_ref_res_and_quit(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	SfCryptoFixture *fixture = user_data;

	(void)source_object;

	fixture->test_res = g_object_ref(res);
	g_test_queue_unref(fixture->test_res);
	g_main_loop_quit(fixture->loop);
}

static void tst_crypto_create_manager(SfCryptoFixture *fixture,
		gconstpointer data)
{
	(void)data;
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->manager);
}

static void tst_crypto_get_plugin_info(SfCryptoFixture *fixture,
		gconstpointer data)
{
	GSList *plgns[] = { (GSList *)0xdeadbeef, NULL };
	gsize i;

	(void)data;

	if (!fixture->manager) {
		g_test_skip("No manager");
		return;
	}

	sf_crypto_manager_get_plugin_info(fixture->manager,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_crypto_manager_get_plugin_info_finish(
			fixture->test_res,
			&plgns[0],
			&plgns[1],
			&fixture->error);
	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	for (i = 0; i < G_N_ELEMENTS(plgns); i++) {
		while (plgns[i]) {
			g_debug("Found plugin: %s", ((SfSecretsPluginInfo *)plgns[i]->data)->name);
			sf_crypto_plugin_info_free(plgns[i]->data);
			plgns[i] = g_slist_delete_link(plgns[i], plgns[i]);
		}
	}
}

static void tst_crypto_generate_random_data(SfCryptoFixture *fixture,
		gconstpointer data)
{
	GBytes *random_bytes;
	(void)data;

	sf_crypto_manager_generate_random_data(fixture->manager,
			4096,
			SF_CRYPTO_DEFAULT_CSPRNG_ENGINE,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	random_bytes = sf_crypto_manager_generate_random_data_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	g_assert_nonnull(random_bytes);

	if (g_test_failed())
		return;

	g_assert_cmpint(g_bytes_get_size(random_bytes), ==, 4096);
	g_bytes_unref(random_bytes);
}

struct key_details {
	SfCryptoAlgorithm algorithm;
	SfCryptoEncryptionPadding padding;
	SfCryptoBlockMode block_mode;
	gint32 key_size;
	gsize data_size;
};

static void tst_crypto_generate_key(SfCryptoFixture *fixture,
		gconstpointer data)
{
	SfCryptoKey *key = g_object_new(SF_TYPE_CRYPTO_KEY,
			"algorithm", SF_CRYPTO_ALGORITHM_AES,
			"key-size", 256,
			NULL);

	(void)data;

	sf_crypto_manager_generate_key(fixture->manager,
			key,
			NULL, NULL,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	key = sf_crypto_manager_generate_key_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_object_unref(key);
}

static SfCryptoKpgParams *_tst_crypto_kpg_params(SfCryptoKey *key)
{
	static SfCryptoKpgParams kpg_params;
	memset(&kpg_params, 0, sizeof(kpg_params));

	switch (sf_crypto_key_get_algorithm(key)) {
	case SF_CRYPTO_ALGORITHM_RSA:
		kpg_params.type = SF_CRYPTO_KEY_PAIR_TYPE_RSA;
		kpg_params.type_params = g_hash_table_new_full(g_str_hash, g_str_equal,
				NULL, (GDestroyNotify)g_variant_unref);
		g_test_queue_destroy((GDestroyNotify)g_hash_table_unref, kpg_params.type_params);
		g_hash_table_insert(kpg_params.type_params, "modulusLength", g_variant_ref_sink(g_variant_new_int32(sf_crypto_key_get_key_size(key))));
		g_hash_table_insert(kpg_params.type_params, "numberPrimes", g_variant_ref_sink(g_variant_new_int32(2)));
		g_hash_table_insert(kpg_params.type_params, "publicExponent", g_variant_ref_sink(g_variant_new_int32(65537)));

		return &kpg_params;
	case SF_CRYPTO_ALGORITHM_EC:
		kpg_params.type = SF_CRYPTO_KEY_PAIR_TYPE_EC;
		kpg_params.type_params = g_hash_table_new_full(g_str_hash, g_str_equal,
				NULL, (GDestroyNotify)g_variant_unref);
		g_test_queue_destroy((GDestroyNotify)g_hash_table_unref, kpg_params.type_params);
		g_hash_table_insert(kpg_params.type_params, "ellipticCurve", g_variant_ref_sink(g_variant_new_int32(SF_CRYPTO_CURVE_SECP384R1)));
		return &kpg_params;
	default:
		return NULL;
	}
}

static void tst_crypto_encrypt_decrypt(SfCryptoFixture *fixture,
		gconstpointer data)
{
	const struct key_details *kd = data;
	SfCryptoKey *key = g_object_new(SF_TYPE_CRYPTO_KEY,
			"algorithm", kd->algorithm,
			"key-size", kd->key_size,
			NULL);
	gint8 *buffer;
	GBytes *secret_data;
	GBytes *iv;
	GBytes *tag;
	gsize i;

	(void)data;

	buffer = g_malloc(kd->data_size);
	g_test_queue_free(buffer);

	sf_crypto_manager_generate_key(fixture->manager,
			key,
			_tst_crypto_kpg_params(key), NULL,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	key = sf_crypto_manager_generate_key_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_object_ref_sink(key);

	sf_crypto_manager_generate_initialization_vector(fixture->manager,
			sf_crypto_key_get_algorithm(key),
			kd->block_mode,
			sf_crypto_key_get_key_size(key),
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);
	iv = sf_crypto_manager_generate_initialization_vector_finish(fixture->test_res, &fixture->error);

	g_test_queue_unref(key);
	g_assert_no_error(fixture->error);

	if (g_test_failed())
		return;

	g_test_queue_destroy((GDestroyNotify)g_bytes_unref, iv);

	for (i = 0; i < kd->data_size; i++)
		buffer[i] = g_test_rand_int_range(0, G_MAXUINT8);

	secret_data = g_bytes_new_static(buffer, kd->data_size);

	sf_crypto_manager_encrypt(fixture->manager,
			secret_data,
			iv,
			key,
			kd->block_mode,
			kd->padding,
			NULL, NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_bytes_unref(secret_data);

	g_main_loop_run(fixture->loop);

	secret_data = sf_crypto_manager_encrypt_finish(fixture->test_res, &tag, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	if (tag)
		g_bytes_unref(tag);

	sf_crypto_manager_decrypt(fixture->manager,
			secret_data,
			iv,
			key,
			kd->block_mode,
			kd->padding,
			NULL, tag,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_bytes_unref(secret_data);

	g_main_loop_run(fixture->loop);

	secret_data = sf_crypto_manager_decrypt_finish(fixture->test_res, NULL, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_assert_cmpmem(g_bytes_get_data(secret_data, NULL), g_bytes_get_size(secret_data),
			buffer, kd->data_size);
	g_bytes_unref(secret_data);
}

static void tst_crypto_encrypt_decrypt_stored(SfCryptoFixture *fixture,
		gconstpointer data)
{
	const struct key_details *kd = data;
	SfCryptoKey *key;
	SfSecretsManager *sm;
	gint8 buffer[1024];
	GBytes *secret_data;
	GBytes *iv;
	GBytes *tag;
	gchar **key_names;
	gsize i;

	sf_secrets_manager_new(NULL, _tst_crypto_ref_res_and_quit, fixture);
	g_main_loop_run(fixture->loop);
	sm = sf_secrets_manager_new_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_test_queue_unref(sm);

	sf_secrets_manager_create_collection(
			sm,
			SECRETS_PLUGIN_STORAGE_TEST,
			SECRETS_PLUGIN_ENCRYPTION_TEST,
			NULL,
			"tst_capi_collection",
			SF_SECRETS_DEVICE_UNLOCK_SEMANTIC_KEEP_UNLOCKED,
			SF_SECRETS_ACCESS_CONTROL_MODE_OWNER_ONLY,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_create_collection_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	sf_crypto_manager_generate_stored_key(fixture->manager,
			g_object_new(SF_TYPE_CRYPTO_KEY,
				"name", "tst_crypto_key",
				"collection-name", "tst_capi_collection",
				"plugin-name", SECRETS_PLUGIN_STORAGE_TEST,
				"algorithm", kd->algorithm,
				"key-size", kd->key_size,
				NULL),
			NULL, NULL,
			NULL, SF_CRYPTO_INPUT_TYPE_UNKNOWN, SF_CRYPTO_ECHO_MODE_UNKNOWN,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	key = sf_crypto_manager_generate_stored_key_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_object_ref_sink(key);
	g_test_queue_unref(key);

	sf_crypto_manager_generate_initialization_vector(fixture->manager,
			sf_crypto_key_get_algorithm(key),
			kd->block_mode,
			sf_crypto_key_get_key_size(key),
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	iv = sf_crypto_manager_generate_initialization_vector_finish(fixture->test_res, &fixture->error);
	g_test_queue_destroy((GDestroyNotify)g_bytes_unref, iv);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	for (i = 0; i < G_N_ELEMENTS(buffer); i++)
		buffer[i] = g_test_rand_int_range(0, G_MAXUINT8);

	secret_data = g_bytes_new_static(buffer, sizeof(buffer));

	sf_crypto_manager_encrypt(fixture->manager,
			secret_data,
			iv,
			key,
			kd->block_mode,
			kd->padding,
			NULL, NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_bytes_unref(secret_data);

	g_main_loop_run(fixture->loop);

	secret_data = sf_crypto_manager_encrypt_finish(fixture->test_res, &tag, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	sf_crypto_manager_decrypt(fixture->manager,
			secret_data,
			iv,
			key,
			kd->block_mode,
			kd->padding,
			NULL, tag,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	if (tag)
		g_bytes_unref(tag);
	g_bytes_unref(secret_data);

	g_main_loop_run(fixture->loop);

	secret_data = sf_crypto_manager_decrypt_finish(fixture->test_res, NULL, &fixture->error);

	g_assert_cmpmem(g_bytes_get_data(secret_data, NULL), g_bytes_get_size(secret_data),
			buffer, sizeof(buffer));
	g_bytes_unref(secret_data);

	sf_crypto_manager_stored_key_names(fixture->manager,
			SECRETS_PLUGIN_STORAGE_TEST,
			"tst_capi_collection",
			NULL, NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	key_names = sf_crypto_manager_stored_key_names_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;
	g_assert_cmpint(g_strv_length(key_names), ==, 1);
	g_assert_cmpstr(key_names[0], ==, sf_crypto_key_get_name(key));

	g_strfreev(key_names);

	sf_crypto_manager_delete_stored_key(fixture->manager,
			"tst_crypto_key",
			"tst_capi_collection",
			SECRETS_PLUGIN_STORAGE_TEST,
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_crypto_manager_delete_stored_key_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);

	sf_secrets_manager_delete_collection(
			sm,
			SECRETS_PLUGIN_STORAGE_TEST,
			"tst_capi_collection",
			NULL,
			_tst_secret_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	sf_secrets_manager_delete_collection_finish(fixture->test_res,
			&fixture->error);
	g_assert_no_error(fixture->error);
}

struct import_key_details {
	const gchar *data;
	const gchar *key_type;
	SfCryptoAlgorithm algorithm;
	gint32 key_size;
};

static void tst_crypto_import_key(SfCryptoFixture *fixture,
		gconstpointer data)
{
	const struct import_key_details *ikd = data;
	SfCryptoKey *key;
	GBytes *bytes;

	(void)data;

	bytes = g_bytes_new_static(ikd->data, strlen(ikd->data));
	g_test_queue_destroy((GDestroyNotify)g_bytes_unref, bytes);

	sf_crypto_manager_import_key(fixture->manager,
			bytes,
			NULL, SF_CRYPTO_INPUT_TYPE_UNKNOWN, SF_CRYPTO_ECHO_MODE_UNKNOWN,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	key = sf_crypto_manager_import_key_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_test_queue_unref(key);

	g_object_get(key, ikd->key_type, &bytes, NULL);

	g_assert_nonnull(bytes);
	g_assert_cmpint(sf_crypto_key_get_algorithm(key), ==, ikd->algorithm);
	g_assert_cmpint(sf_crypto_key_get_key_size(key), ==, ikd->key_size);

	g_bytes_unref(bytes);
}

struct digest_details {
	gsize data_size;
	GChecksumType g_digest;
	SfCryptoDigest sf_digest;
};

static void tst_crypto_digest(SfCryptoFixture *fixture,
		gconstpointer data)
{
	const struct digest_details *dd = data;
	gchar *buffer = g_malloc(dd->data_size);
	GBytes *bytes;
	GBytes *digest;
	GChecksum *gcs;
	guchar *gdigest;
	gsize i;

	for (i = 0; i < dd->data_size; i++)
		buffer[i] = g_test_rand_int_range(0, G_MAXUINT8);
	bytes = g_bytes_new_take(buffer, dd->data_size);

	g_test_queue_destroy((GDestroyNotify)g_bytes_unref, bytes);

	sf_crypto_manager_calculate_digest(fixture->manager,
			bytes,
			SF_CRYPTO_SIGNATURE_PADDING_NONE,
			dd->sf_digest,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	digest = sf_crypto_manager_calculate_digest_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	gcs = g_checksum_new(dd->g_digest);
	g_checksum_update(gcs, g_bytes_get_data(bytes, NULL), g_bytes_get_size(bytes));
	gdigest = g_malloc((i = g_checksum_type_get_length(dd->g_digest)));
	g_checksum_get_digest(gcs, gdigest, &i);
	g_checksum_free(gcs);

	g_assert_cmpmem(g_bytes_get_data(digest, NULL), g_bytes_get_size(digest),
			gdigest, i);

	g_bytes_unref(digest);
	g_free(gdigest);
}

static void tst_crypto_sign_verify(SfCryptoFixture *fixture,
		gconstpointer data)
{
	const struct key_details *kd = data;
	SfCryptoKey *key = g_object_new(SF_TYPE_CRYPTO_KEY,
			"algorithm", kd->algorithm,
			"key-size", kd->key_size,
			NULL);
	gint8 *buffer;
	GBytes *secret_data;
	GBytes *signature;
	SfCryptoVerificationStatus verify_status;

	(void)data;

	buffer = g_malloc(kd->data_size);
	g_test_queue_free(buffer);

	sf_crypto_manager_generate_key(fixture->manager,
			key,
			_tst_crypto_kpg_params(key), NULL,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	key = sf_crypto_manager_generate_key_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_object_ref_sink(key);
	g_test_queue_unref(key);

	sf_crypto_manager_generate_random_data(fixture->manager,
			kd->data_size,
			SF_CRYPTO_DEFAULT_CSPRNG_ENGINE,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);
	g_main_loop_run(fixture->loop);

	secret_data = sf_crypto_manager_generate_random_data_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	g_assert_nonnull(secret_data);

	if (g_test_failed())
		return;

	g_test_queue_destroy((GDestroyNotify)g_bytes_unref, secret_data);

	sf_crypto_manager_sign(fixture->manager,
			secret_data,
			key,
			kd->padding,
			SF_CRYPTO_DIGEST_SHA256,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);

	g_main_loop_run(fixture->loop);

	signature = sf_crypto_manager_sign_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_test_queue_destroy((GDestroyNotify)g_bytes_unref, signature);

	sf_crypto_manager_verify(fixture->manager,
			signature,
			secret_data,
			key,
			kd->padding,
			SF_CRYPTO_DIGEST_SHA256,
			NULL,
			CRYPTO_PLUGIN_TEST,
			NULL,
			_tst_crypto_ref_res_and_quit,
			fixture);

	g_main_loop_run(fixture->loop);

	verify_status = sf_crypto_manager_verify_finish(fixture->test_res, &fixture->error);

	g_assert_no_error(fixture->error);
	g_assert_cmpint(verify_status, ==, SF_CRYPTO_VERIFICATION_STATUS_SUCCEEDED);
	if (g_test_failed())
		return;
}

static void _tst_secret_setup_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	SfSecretsFixture *fixture = user_data;

	(void)source_object;

	fixture->manager = sf_secrets_manager_new_finish(res, &fixture->error);
	g_main_loop_quit(fixture->loop);
}

static void tst_secret_setup(SfSecretsFixture *fixture,
		gconstpointer data)
{
	(void)data;
	fixture->error = NULL;
	fixture->test_res = NULL;
	fixture->loop = g_main_loop_new(NULL, TRUE);
	sf_secrets_manager_new(NULL, _tst_secret_setup_ready, fixture);
	if (g_main_loop_is_running(fixture->loop))
		g_main_loop_run(fixture->loop);
}

static void tst_secret_teardown(SfSecretsFixture *fixture,
		gconstpointer data)
{
	(void)data;
	g_main_loop_unref(fixture->loop);
	if (fixture->manager)
		g_object_unref(fixture->manager);
	if (fixture->error)
		g_error_free(fixture->error);
}

static void _tst_crypto_setup_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	SfCryptoFixture *fixture = user_data;

	(void)source_object;

	fixture->manager = sf_crypto_manager_new_finish(res, &fixture->error);
	g_main_loop_quit(fixture->loop);
}

static void tst_crypto_setup(SfCryptoFixture *fixture,
		gconstpointer data)
{
	(void)data;
	fixture->error = NULL;
	fixture->test_res = NULL;
	fixture->loop = g_main_loop_new(NULL, TRUE);
	sf_crypto_manager_new(NULL, _tst_crypto_setup_ready, fixture);
	if (g_main_loop_is_running(fixture->loop))
		g_main_loop_run(fixture->loop);
}

static void tst_crypto_teardown(SfCryptoFixture *fixture,
		gconstpointer data)
{
	(void)data;
	g_main_loop_unref(fixture->loop);
	if (fixture->manager)
		g_object_unref(fixture->manager);
	if (fixture->error)
		g_error_free(fixture->error);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_set_nonfatal_assertions();

#define sf_secret_test(name, test) \
	g_test_add("/Secrets/" name, SfSecretsFixture, NULL, \
			tst_secret_setup, test, tst_secret_teardown)

	sf_secret_test("CreateManager", tst_secret_create_manager);
	sf_secret_test("GetPluginInfo", tst_secret_get_plugin_info);
	sf_secret_test("GetHealthInfo", tst_secret_get_health_info);
	sf_secret_test("CollectionNames", tst_secret_collection_names);
	sf_secret_test("CreateDeleteCollection", tst_secret_create_delete_collection);
	sf_secret_test("SetGetStandaloneSecret", tst_secret_set_get_standalone_secret);
	sf_secret_test("SetGetCollectionSecret", tst_secret_set_get_collection_secret);
	sf_secret_test("SetFindDeleteCollectionSecret", tst_secret_set_find_delete_collection_secret);
#undef sf_secret_test

#define sf_crypto_test(name, test, data) \
	g_test_add("/Crypto/" name, SfCryptoFixture, data, \
			tst_crypto_setup, test, tst_crypto_teardown)
	sf_crypto_test("CreateManager", tst_crypto_create_manager, NULL);
	sf_crypto_test("GetPluginInfo", tst_crypto_get_plugin_info, NULL);
	sf_crypto_test("GenerateRandomData", tst_crypto_generate_random_data, NULL);
	sf_crypto_test("GenerateKey", tst_crypto_generate_key, NULL);
	sf_crypto_test("EncryptDecryptAesCbc128", tst_crypto_encrypt_decrypt, (&(struct key_details){
		.algorithm = SF_CRYPTO_ALGORITHM_AES,
		.padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
		.block_mode = SF_CRYPTO_BLOCK_MODE_CBC,
		.key_size = 128,
	        .data_size = 1024 }));
	sf_crypto_test("EncryptDecryptAesCbc192", tst_crypto_encrypt_decrypt, (&(struct key_details){
		.algorithm = SF_CRYPTO_ALGORITHM_AES,
		.padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
		.block_mode = SF_CRYPTO_BLOCK_MODE_CBC,
		.key_size = 192,
		.data_size = 2048 }));
	sf_crypto_test("EncryptDecryptAesCbc256", tst_crypto_encrypt_decrypt, (&(struct key_details){
		.algorithm = SF_CRYPTO_ALGORITHM_AES,
		.padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
		.block_mode = SF_CRYPTO_BLOCK_MODE_CBC,
		.key_size = 256,
		.data_size = 4096 }));
	sf_crypto_test("EncryptDecryptRsa2048", tst_crypto_encrypt_decrypt, (&(struct key_details){
		.algorithm = SF_CRYPTO_ALGORITHM_RSA,
		.padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
		.block_mode = SF_CRYPTO_BLOCK_MODE_UNKNOWN,
		.key_size = 2048,
		.data_size = 256 }));
	sf_crypto_test("EncryptDecryptRsa4096", tst_crypto_encrypt_decrypt, (&(struct key_details){
		.algorithm = SF_CRYPTO_ALGORITHM_RSA,
		.padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
		.block_mode = SF_CRYPTO_BLOCK_MODE_UNKNOWN,
		.key_size = 4096,
		.data_size = 512 }));
	sf_crypto_test("EncryptDecryptStoredAesCbc128", tst_crypto_encrypt_decrypt_stored, (&(struct key_details){
		.algorithm = SF_CRYPTO_ALGORITHM_AES,
		.padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
		.block_mode = SF_CRYPTO_BLOCK_MODE_CBC,
		.key_size = 128 }));
	sf_crypto_test("ImportKeyRsa1024", tst_crypto_import_key, (&(struct import_key_details){
		.data = "-----BEGIN RSA PRIVATE KEY-----\n"
			"MIICXQIBAAKBgQCiqCTjlgV2LMhFSnBOn/QDMUmxJXeMd9umc44nMnBYeI4C225t\n"
			"BQEqqUReAgxz+nuMJ8LUP4T2LQeYAFbOD99NEOLI4a1HCr+uxFWH3dfxr+BNZzsq\n"
			"iUQSSVeO1i4WQ9sBMLJrHGOCSLBfroKfdGFdncxvWBqk73AQSl2YzQ72owIDAQAB\n"
			"AoGAbNMAcz/hAZKunyVRhFkiAazNN/bwSAu86l1voyvs3FQz9xdmhwwNHsTG1/qY\n"
			"6FOSq0/C2wxwYd/4r6qyaQVXiP/TQS61Vy/LnAyGpQ17l4UWCTH2vNgzarnrDUxt\n"
			"nwZ46soZVsO1XfLZr+v/h5X9FqaZwsGGt/A5g1uGksN/snECQQDUzLf5y2htHatv\n"
			"RBIQyUnvejJEHQhpM3xQShqpIS91DFM/HmfM5ERUg9YO23eOXAmY6J6Chys3DN2a\n"
			"Fvu7Z2DpAkEAw617MhMfp9n1UbOA/5vh4aJUDPwCK+1T4Re77xlFTBz70rcXYgoP\n"
			"TxNREW5BpKkv9mJ8RJwOKf70JAMzYtqDqwJBANCqjh0cIKIe3eSVU0GyoBV8NZ4k\n"
			"+gJuwg/ZGpuONwMHuvnBzvdTPs3BGT4oZuvpxF90ezpzYSTyMLrQnrf9f0ECQC9y\n"
			"WkPrFSrrE6vq3aWdE6lVZhH77T7ffg4/Zgd01jO9d2ZBlP7lt46R/X8/f9VAXOve\n"
			"N4mfWWPfeS1eRVB78Z8CQQCM5gzW8QjXX/PyuF+CcQx2WkYr3I4btXnKJaU3g0ED\n"
			"tJSXNq/ZZfAXKa42id05ee2F1ek26dBlOPrXguXO7UlC\n"
			"-----END RSA PRIVATE KEY-----\n",
		.key_type = "private-key",
		.algorithm = SF_CRYPTO_ALGORITHM_RSA,
		.key_size = 1024 }));
	sf_crypto_test("ImportKeyPubRsa1024", tst_crypto_import_key, (&(struct import_key_details){
		.data = "-----BEGIN PUBLIC KEY-----\n"
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiqCTjlgV2LMhFSnBOn/QDMUmx\n"
			"JXeMd9umc44nMnBYeI4C225tBQEqqUReAgxz+nuMJ8LUP4T2LQeYAFbOD99NEOLI\n"
			"4a1HCr+uxFWH3dfxr+BNZzsqiUQSSVeO1i4WQ9sBMLJrHGOCSLBfroKfdGFdncxv\n"
			"WBqk73AQSl2YzQ72owIDAQAB\n"
			"-----END PUBLIC KEY-----\n",
		.key_type = "public-key",
		.algorithm = SF_CRYPTO_ALGORITHM_RSA,
		.key_size = 1024 }));
	sf_crypto_test("DigestMd5", tst_crypto_digest, (&(struct digest_details){
		.data_size = 1024,
		.g_digest = G_CHECKSUM_MD5,
		.sf_digest = SF_CRYPTO_DIGEST_MD5}));
	sf_crypto_test("DigestSha256", tst_crypto_digest, (&(struct digest_details){
		.data_size = 2048,
		.g_digest = G_CHECKSUM_SHA256,
		.sf_digest = SF_CRYPTO_DIGEST_SHA256}));
	sf_crypto_test("DigestSha512", tst_crypto_digest, (&(struct digest_details){
		.data_size = 4096,
		.g_digest = G_CHECKSUM_SHA512,
		.sf_digest = SF_CRYPTO_DIGEST_SHA512}));
	sf_crypto_test("SignVerifyRsa2048", tst_crypto_sign_verify, (&(struct key_details){
		.algorithm = SF_CRYPTO_ALGORITHM_RSA,
		.padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
		.block_mode = SF_CRYPTO_BLOCK_MODE_UNKNOWN,
		.key_size = 2048,
		.data_size = 256 }));
#undef sf_secret_test

	g_test_run();

	return 0;
}
