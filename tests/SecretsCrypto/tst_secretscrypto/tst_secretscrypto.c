#include <SecretsCrypto/sf-secrets-manager.h>
#include <glib.h>

#define SECRETS_PLUGIN_STORAGE_TEST "org.sailfishos.secrets.plugin.storage.sqlite.test"
#define SECRETS_PLUGIN_ENCRYPTION_TEST "org.sailfishos.secrets.plugin.encryption.openssl.test"

typedef struct SfSecretsFixture_ {
	GMainLoop *loop;
	GError *error;
	SfSecretsManager *manager;
	GAsyncResult *test_res;
} SfSecretsFixture;

static void _tst_secret_ref_res_and_quit(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	SfSecretsFixture *fixture = user_data;

	(void)source_object;

	fixture->test_res = g_object_ref(res);
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

	g_object_unref(fixture->test_res);
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

	g_object_unref(fixture->test_res);
	fixture->test_res = NULL;

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

	g_object_unref(fixture->test_res);
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

	g_object_unref(fixture->test_res);
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

	g_object_unref(fixture->test_res);
	fixture->test_res = NULL;

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

	g_object_unref(fixture->test_res);
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

	g_assert_no_error(fixture->error);
	if (g_test_failed())
		return;

	g_assert_cmpint(g_strv_length(secret_names), ==, 1);
	if (!g_test_failed())
		g_assert_cmpstr(secret_names[0], ==, "tst_capi_secret");

	if (g_test_failed()) {
		g_strfreev(secret_names);
		return;
	}

	g_object_unref(fixture->test_res);
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

	g_object_unref(fixture->test_res);
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

	g_object_unref(fixture->test_res);
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
	if (fixture->test_res)
		g_object_unref(fixture->test_res);
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

	g_test_run();

	return 0;
}
