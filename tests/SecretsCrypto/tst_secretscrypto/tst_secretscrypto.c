#include <SecretsCrypto/sf-secrets-manager.h>
#include <SecretsCrypto/sf-secrets-interaction-request.h>
#include <SecretsCrypto/sf-crypto-manager.h>
#include <SecretsCrypto/sf-crypto-cipher-session.h>
#include <glib.h>

#include <string.h>

#define SECRETS_PLUGIN_STORAGE_TEST "org.sailfishos.secrets.plugin.storage.sqlite.test"
#define SECRETS_PLUGIN_ENCRYPTION_TEST "org.sailfishos.secrets.plugin.encryption.openssl.test"
#define SECRETS_PLUGIN_INAPP_AUTH_TEST "org.sailfishos.secrets.plugin.authentication.inapp.test"
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
    gpointer test_data;
} SfCryptoFixture;

static GBytes *_fuzz_bytes_take(GBytes *from, gsize fuzz)
{
    GByteArray *data = g_bytes_unref_to_array(from);
    gsize i;

    if (fuzz > data->len)
        fuzz = data->len;

    for (i = 0; i < fuzz; i++)
        data->data[g_test_rand_int_range(0, data->len)] ^= g_test_rand_int_range(1, (gint)G_MAXUINT8 + 1);

    return g_byte_array_free_to_bytes(data);
}

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

static void tst_secret_set_no_collection(SfSecretsFixture *fixture,
        gconstpointer data)
{
    SfSecretsSecret *secret;
    GBytes *sec_data;

    (void)data;

    if (!fixture->manager) {
        g_test_skip("No manager");
        return;
    }

    sec_data = g_bytes_new_static("tst_capi", 8);
    secret = g_object_new(SF_TYPE_SECRETS_SECRET,
            "data", sec_data,
            "plugin-name", SECRETS_PLUGIN_STORAGE_TEST,
            "name", "tst_capi_secret",
            NULL);
    g_bytes_unref(sec_data);

    g_object_add_weak_pointer(G_OBJECT(secret), (gpointer *)&secret);

    sf_secrets_manager_set_secret(fixture->manager,
            secret,
            NULL,
            _tst_secret_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    sf_secrets_manager_set_secret_finish(fixture->test_res, &fixture->error);

    g_assert_error(fixture->error,
            SF_SECRETS_ERROR, SF_SECRETS_ERROR_INVALID_COLLECTION);
    g_assert_null(secret);
}

static void tst_secret_set_standalone_with_collection(SfSecretsFixture *fixture,
        gconstpointer data)
{
    SfSecretsSecret *secret;
    GBytes *sec_data;

    (void)data;

    if (!fixture->manager) {
        g_test_skip("No manager");
        return;
    }

    sec_data = g_bytes_new_static("tst_capi", 8);
    secret = g_object_new(SF_TYPE_SECRETS_SECRET,
            "data", sec_data,
            "plugin-name", SECRETS_PLUGIN_STORAGE_TEST,
            "collection-name", "tst_capi_collection",
            "name", "tst_capi_secret",
            NULL);
    g_bytes_unref(sec_data);

    g_object_add_weak_pointer(G_OBJECT(secret), (gpointer *)&secret);

    sf_secrets_manager_set_secret_standalone(fixture->manager,
            secret,
            SECRETS_PLUGIN_ENCRYPTION_TEST,
            NULL,
            SF_SECRETS_DEVICE_UNLOCK_SEMANTIC_KEEP_UNLOCKED,
            SF_SECRETS_ACCESS_CONTROL_MODE_OWNER_ONLY,
            NULL,
            _tst_secret_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    sf_secrets_manager_set_secret_finish(fixture->test_res, &fixture->error);

    g_assert_error(fixture->error,
            SF_SECRETS_ERROR, SF_SECRETS_ERROR_INVALID_COLLECTION);
    g_assert_null(secret);
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

static void tst_secret_collections_nonexistent_plugin(SfSecretsFixture *fixture,
        gconstpointer data)
{
    gchar **names;

    (void)data;

    sf_secrets_manager_collection_names(fixture->manager,
            "tst_capi_nonexistent_plugin",
            NULL,
            _tst_secret_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    names = sf_secrets_manager_collection_names_finish(fixture->test_res, &fixture->error);
    g_assert_error(fixture->error,
            SF_SECRETS_ERROR,
            SF_SECRETS_ERROR_INVALID_EXTENSION_PLUGIN);
    g_assert_null(names);

    if (names)
        g_strfreev(names);
}

static void tst_secret_get_from_nonexistent_collection(SfSecretsFixture *fixture,
        gconstpointer data)
{
    SfSecretsSecret *secret;

    (void)data;

    sf_secrets_manager_get_secret(fixture->manager,
            "tst_capi_secret",
            "tst_capi_nonexistent_collection",
            SECRETS_PLUGIN_STORAGE_TEST,
            NULL,
            _tst_secret_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    secret = sf_secrets_manager_get_secret_finish(fixture->test_res, &fixture->error);

    g_assert_error(fixture->error,
                    SF_SECRETS_ERROR,
                    SF_SECRETS_ERROR_INVALID_COLLECTION);
    g_assert_null(secret);
}

static void tst_secret_create_existing_collection(SfSecretsFixture *fixture,
        gconstpointer data)
{
    (void)data;

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

    g_assert_no_error(fixture->error);
    if (g_test_failed())
        return;

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

    g_assert_error(fixture->error, SF_SECRETS_ERROR,
                    SF_SECRETS_ERROR_COLLECTION_ALREADY_EXISTS);
    g_clear_error(&fixture->error);

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
    g_assert_error(fixture->error, SF_SECRETS_ERROR,
            SF_SECRETS_ERROR_INVALID_COLLECTION);
}

static void _tst_secret_interaction_request_continue(SfSecretsInteractionRequest *request,
        SfSecretsFixture *fixture)
{
    GBytes *b;
    (void)fixture;
    (void)request;

    b = g_bytes_new_static("sailfish", 8);
    sf_secrets_interaction_request_return(request, b);
    g_bytes_unref(b);
}

static gboolean _tst_secret_interaction_request_new_request(SfSecretsManager *manager,
        SfSecretsInteractionRequest *request,
        SfSecretsFixture *fixture)
{
    GBytes *b;

    (void)manager;
    (void)fixture;

    g_signal_connect(request, "continue", G_CALLBACK(_tst_secret_interaction_request_continue), fixture);
    g_signal_connect(request, "finish", G_CALLBACK(g_object_unref), NULL);
    g_signal_connect(request, "cancel", G_CALLBACK(g_object_unref), NULL);

    g_object_ref(request);

    b = g_bytes_new_static("sailfish", 8);
    sf_secrets_interaction_request_return(request, b);
    g_bytes_unref(b);

    return TRUE;
}

static void tst_secret_interaction_request(SfSecretsFixture *fixture,
        gconstpointer data)
{
    (void)data;

    if (!fixture->manager) {
        g_test_skip("No manager");
        return;
    }

    g_object_set(fixture->manager,
            "user-interaction-mode", SF_SECRETS_USER_INTERACTION_MODE_APPLICATION,
            NULL);

    g_signal_connect(fixture->manager, "new-interaction-request",
            G_CALLBACK(_tst_secret_interaction_request_new_request), fixture);
    sf_secrets_manager_create_collection(
            fixture->manager,
            SECRETS_PLUGIN_STORAGE_TEST,
            SECRETS_PLUGIN_ENCRYPTION_TEST,
            SECRETS_PLUGIN_INAPP_AUTH_TEST,
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
    gsize chunks;
    gsize fuzz_sig;
    gsize fuzz_data;
    SfCryptoVerificationStatus expected_status;
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

static void tst_crypto_nonexistent_stored_key(SfCryptoFixture *fixture,
        gconstpointer data)
{
    SfCryptoKey *key;
    SfSecretsManager *sm;

    (void)data;

    sf_crypto_manager_stored_key(fixture->manager,
            "tst_capi_key",
            "tst_capi_collection",
            SECRETS_PLUGIN_STORAGE_TEST,
            SF_CRYPTO_KEY_CONSTRAINT_NO_DATA,
            NULL,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    key = sf_crypto_manager_stored_key_finish(fixture->test_res, &fixture->error);

    g_assert_error(fixture->error,
            SF_SECRETS_ERROR, SF_SECRETS_ERROR_INVALID_COLLECTION);
    g_assert_null(key);

    g_clear_error(&fixture->error);

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

    sf_crypto_manager_stored_key(fixture->manager,
            "tst_capi_key",
            "tst_capi_collection",
            SECRETS_PLUGIN_STORAGE_TEST,
            SF_CRYPTO_KEY_CONSTRAINT_NO_DATA,
            NULL,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    key = sf_crypto_manager_stored_key_finish(fixture->test_res, &fixture->error);

    g_assert_error(fixture->error,
            SF_SECRETS_ERROR, SF_SECRETS_ERROR_INVALID_SECRET);
    g_assert_null(key);
    g_clear_error(&fixture->error);

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

    if (kd->fuzz_data)
        secret_data = _fuzz_bytes_take(secret_data, kd->fuzz_data);
    g_test_queue_destroy((GDestroyNotify)g_bytes_unref, secret_data);

    signature = sf_crypto_manager_sign_finish(fixture->test_res, &fixture->error);

    g_assert_no_error(fixture->error);
    if (g_test_failed())
        return;

    if (kd->fuzz_sig)
        signature = _fuzz_bytes_take(signature, kd->fuzz_sig);
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
    g_assert_cmpint(verify_status, ==, kd->expected_status);
    if (g_test_failed())
        return;
}

static void tst_crypto_import_verify(SfCryptoFixture *fixture, gconstpointer test_data)
{
    SfCryptoKey *key;
    const gchar data[] = "Test secret data\n";
    /* From openssl genrsa; openssl dgst -sha256 -sign */
    const gchar signature[] = {
        0x2b, 0xee, 0x71, 0x11, 0x4b, 0x48, 0xe6, 0x3f, 0xc1, 0x19, 0x3c,
        0x42, 0x7d, 0x68, 0xd5, 0x3a, 0x35, 0x0b, 0x41, 0x92, 0x9f, 0x3c,
        0xeb, 0xbb, 0x85, 0x77, 0xe9, 0x8d, 0x35, 0xfb, 0x4c, 0x1b, 0x60,
        0xad, 0x9f, 0xed, 0x2e, 0xcc, 0x49, 0xef, 0x2e, 0xbb, 0xf8, 0xdf,
        0xc5, 0xb0, 0xd1, 0xa7, 0x88, 0x67, 0x03, 0xc4, 0xe2, 0x41, 0xa0,
        0x2d, 0x65, 0x2e, 0xae, 0x82, 0x48, 0xbf, 0x58, 0x18, 0x54, 0x3f,
        0xcc, 0xc2, 0xb5, 0xe4, 0xf4, 0x88, 0x46, 0xd3, 0x90, 0xd0, 0x52,
        0x6d, 0xca, 0x4e, 0x5c, 0xeb, 0xde, 0xed, 0x62, 0xb2, 0xd6, 0x6e,
        0x12, 0x0b, 0x96, 0x9d, 0xf6, 0xb0, 0x4d, 0xf6, 0x2f, 0x41, 0x2a,
        0xcf, 0x9d, 0xb6, 0xa9, 0xc0, 0x70, 0x25, 0xa8, 0x54, 0x37, 0xff,
        0x02, 0xe2, 0xf9, 0x8d, 0xc8, 0xc0, 0xa6, 0x65, 0x23, 0x2c, 0xdc,
        0x03, 0xf6, 0xb5, 0x71, 0xca, 0x27, 0x14, 0xb6, 0xf9, 0xb6, 0x30,
        0x0e, 0x44, 0x77, 0x60, 0x64, 0x7d, 0x3a, 0xa9, 0xa8, 0xcb, 0x05,
        0x04, 0xf1, 0x3e, 0x69, 0xf3, 0xf4, 0xa6, 0x91, 0xbe, 0x5e, 0x7d,
        0x07, 0x05, 0x7d, 0xd3, 0xaf, 0x23, 0x9c, 0x9a, 0x9c, 0xc0, 0x85,
        0x71, 0x88, 0x99, 0xbe, 0x48, 0x00, 0xab, 0xa2, 0x27, 0x26, 0x20,
        0x96, 0xb5, 0x84, 0x50, 0x7f, 0x97, 0xbe, 0x9c, 0x45, 0xf7, 0x4c,
        0x3a, 0x1d, 0xec, 0x98, 0xaf, 0x32, 0x42, 0x1d, 0xee, 0x75, 0x97,
        0xf1, 0x57, 0xac, 0x10, 0xde, 0x48, 0xf0, 0x28, 0xc9, 0xcd, 0x8b,
        0xae, 0x42, 0x8b, 0xe8, 0x90, 0x6e, 0xce, 0x69, 0xd9, 0xe9, 0x8d,
        0xa4, 0x80, 0xd4, 0x5d, 0x5d, 0x89, 0xc5, 0x71, 0xd2, 0x8c, 0xa0,
        0x51, 0x40, 0xb3, 0x80, 0x94, 0xb9, 0x68, 0x0d, 0x4c, 0x89, 0xcd,
        0x8a, 0xd9, 0xdf, 0x6d, 0x31, 0x7b, 0x8b, 0x48, 0x89, 0x32, 0x2b,
        0x7a, 0x62, 0x15,
    };

    /* From openssl genrsa; openssl pkey */
    const gchar pubkey[] = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtEhmgAcjb9y3pQWhiWf\n"
        "E+2WMfzFGoZgTsoA0l7HKeNJ1m230VuGbR/Fc4waUmJ7gwZK8gxJoWcItZEj8Box\n"
        "iXOG8SfzYW2CJbVFJi/k47DceBoUk20J0x1zP18zd10k/yS8WUQPTTyzvxZQPCdQ\n"
        "cTDDOkMK6yHrpGCYWfkMAT3y2ufp8XxBkVATbPxegd2H1kyzk9yyfMU2tZZdsCfU\n"
        "nphAyELfCLoEv0md/UH/69JlIXSE4zts8zIhiJuNOZJbH9rklq0DvyrgtRYRahSK\n"
        "1kgn6eHBuZZp1vpVggbOI25Qc7tp392i02QqxFwnOE7XYAJYYEFAoX8/x6XjYVTl\n"
        "qwIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

    GBytes *pub_bytes = g_bytes_new_static(pubkey, G_N_ELEMENTS(pubkey) - 1);
    GBytes *data_bytes = g_bytes_new_static(data, G_N_ELEMENTS(data) - 1);
    GBytes *sig_bytes = g_bytes_new_static(signature, G_N_ELEMENTS(signature));

    SfCryptoVerificationStatus verify_status;

    (void)test_data;

    g_test_queue_destroy((GDestroyNotify)g_bytes_unref, pub_bytes);
    g_test_queue_destroy((GDestroyNotify)g_bytes_unref, data_bytes);
    g_test_queue_destroy((GDestroyNotify)g_bytes_unref, sig_bytes);

    sf_crypto_manager_import_key(fixture->manager,
            pub_bytes,
            NULL, SF_CRYPTO_INPUT_TYPE_UNKNOWN, SF_CRYPTO_ECHO_MODE_UNKNOWN,
            NULL,
            CRYPTO_PLUGIN_TEST,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);
    key = sf_crypto_manager_import_key_finish(fixture->test_res, &fixture->error);

    g_assert_no_error(fixture->error);
    g_assert_nonnull(key);
    if (g_test_failed())
        return;

    sf_crypto_manager_verify(fixture->manager,
            sig_bytes,
            data_bytes,
            key,
            SF_CRYPTO_ENCRYPTION_PADDING_NONE,
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

static void tst_crypto_import_invalid(SfCryptoFixture *fixture, gconstpointer test_data)
{
    SfCryptoKey *key;
    const gchar pubkey[] = "-----BEGIN PUBLIC KEY-----\n"
        "aiuhgiuwey8a6wb7869nw87aenf9876wb876b387af687ew9f6nwae687f6aa98w\n"
        "aihwefiuwefbwauiebfhoawiuendhewafubivy8t94btoweiufniuwbfiuwabiu3\n"
        "awieohfiubwefiuay3298na89obwt98voywki8t632vbt3AWTU49tu8oanwv4twa\n"
        "awuefiuwaefhjkse8tbz7/3wyb+i7vkn3zyrncyrinay4n7tiakytnky4it7ynss\n"
        "acuNlRYsPYbRi0zq/HU/69WyVKFR4mgf8mVuvWhABMWoU9exyd0QiletgELEnuFX\n"
        "aw8b3786bq2837awtaAWEILHWItaiwy4yba8enofWEFAweif6ab7wefAWEFawiel\n"
        "wa832341\n"
        "-----END PUBLIC KEY-----\n";

    GBytes *pub_bytes = g_bytes_new_static(pubkey, G_N_ELEMENTS(pubkey) - 1);

    (void)test_data;

    g_test_queue_destroy((GDestroyNotify)g_bytes_unref, pub_bytes);

    sf_crypto_manager_import_key(fixture->manager,
            pub_bytes,
            NULL, SF_CRYPTO_INPUT_TYPE_UNKNOWN, SF_CRYPTO_ECHO_MODE_UNKNOWN,
            NULL,
            CRYPTO_PLUGIN_TEST,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);
    key = sf_crypto_manager_import_key_finish(fixture->test_res, &fixture->error);

    g_assert_error(fixture->error, SF_CRYPTO_ERROR, SF_CRYPTO_ERROR_CRYPTO_PLUGIN_KEY_IMPORT);
    g_assert_null(key);
}

static void tst_crypto_encrypt_decrypt_session(SfCryptoFixture *fixture,
        gconstpointer data)
{
    const struct key_details *kd = data;
    SfCryptoKey *key = g_object_new(SF_TYPE_CRYPTO_KEY,
            "algorithm", kd->algorithm,
            "key-size", kd->key_size,
            NULL);
    SfCryptoCipherSession *encoder;
    SfCryptoCipherSession *decoder;
    gint8 *buffer;
    GBytes *iv;
    GBytes *remainder;
    gsize i;
    GByteArray *encoded;
    GByteArray *decoded;

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

    sf_crypto_cipher_session_new(fixture->manager,
            iv,
            key,
            SF_CRYPTO_OPERATION_ENCRYPT,
            kd->block_mode,
            kd->padding,
            SF_CRYPTO_SIGNATURE_PADDING_NONE,
            SF_CRYPTO_DIGEST_SHA256,
            NULL,
            CRYPTO_PLUGIN_TEST,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    encoder = sf_crypto_cipher_session_new_finish(fixture->test_res, &fixture->error);

    g_assert_no_error(fixture->error);
    g_assert_nonnull(encoder);

    if (g_test_failed())
        return;

    g_test_queue_unref(encoder);

    sf_crypto_cipher_session_new(fixture->manager,
            iv,
            key,
            SF_CRYPTO_OPERATION_DECRYPT,
            kd->block_mode,
            kd->padding,
            SF_CRYPTO_SIGNATURE_PADDING_NONE,
            SF_CRYPTO_DIGEST_SHA256,
            NULL,
            CRYPTO_PLUGIN_TEST,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    decoder = sf_crypto_cipher_session_new_finish(fixture->test_res, &fixture->error);

    g_assert_no_error(fixture->error);
    g_assert_nonnull(decoder);

    if (g_test_failed())
        return;

    g_test_queue_unref(decoder);

    encoded = g_byte_array_sized_new(kd->data_size * kd->chunks);
    decoded = g_byte_array_sized_new(kd->data_size * kd->chunks);

    g_test_queue_destroy((GDestroyNotify)g_byte_array_unref, encoded);
    g_test_queue_destroy((GDestroyNotify)g_byte_array_unref, decoded);

    for (i = 0; i < kd->chunks; i++) {
        GBytes *random_bytes = NULL;
        GBytes *encoded_bytes;

        sf_crypto_manager_generate_random_data(fixture->manager,
                kd->data_size,
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

        g_byte_array_append(encoded, g_bytes_get_data(random_bytes, NULL), g_bytes_get_size(random_bytes));

        sf_crypto_cipher_session_update(encoder,
                random_bytes,
                NULL,
                NULL,
                _tst_crypto_ref_res_and_quit,
                fixture);
        g_bytes_unref(random_bytes);
        g_main_loop_run(fixture->loop);

        sf_crypto_cipher_session_update_finish(fixture->test_res, &encoded_bytes, &fixture->error);

        g_assert_no_error(fixture->error);
        g_assert_nonnull(encoded_bytes);

        if (g_test_failed())
            return;

        sf_crypto_cipher_session_update(decoder,
                encoded_bytes,
                NULL,
                NULL,
                _tst_crypto_ref_res_and_quit,
                fixture);
        g_bytes_unref(encoded_bytes);
        g_main_loop_run(fixture->loop);

        sf_crypto_cipher_session_update_finish(fixture->test_res, &random_bytes, &fixture->error);

        g_assert_no_error(fixture->error);
        g_assert_nonnull(random_bytes);

        if (g_test_failed())
            return;

        g_byte_array_append(decoded, g_bytes_get_data(random_bytes, NULL), g_bytes_get_size(random_bytes));
        g_bytes_unref(random_bytes);

        g_assert_cmpmem(encoded->data, MIN(encoded->len, decoded->len),
                decoded->data, MIN(decoded->len, encoded->len));
    }

    sf_crypto_cipher_session_close(encoder,
            NULL,
            NULL,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    sf_crypto_cipher_session_close_finish(fixture->test_res, &remainder, NULL, &fixture->error);

    g_assert_no_error(fixture->error);

    if (g_test_failed())
        return;

    if (remainder && g_bytes_get_size(remainder)) {
        sf_crypto_cipher_session_update(decoder,
                remainder,
                NULL,
                NULL,
                _tst_crypto_ref_res_and_quit,
                fixture);
        g_bytes_unref(remainder);
        g_main_loop_run(fixture->loop);

        sf_crypto_cipher_session_update_finish(fixture->test_res, &remainder, &fixture->error);

        g_assert_no_error(fixture->error);
        g_assert_nonnull(remainder);

        if (g_test_failed())
            return;

        g_byte_array_append(decoded, g_bytes_get_data(remainder, NULL), g_bytes_get_size(remainder));
    }
    if (remainder)
        g_bytes_unref(remainder);

    sf_crypto_cipher_session_close(decoder,
            NULL,
            NULL,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    sf_crypto_cipher_session_close_finish(fixture->test_res, &remainder, NULL, &fixture->error);

    g_assert_no_error(fixture->error);

    if (g_test_failed())
        return;

    if (remainder) {
        g_byte_array_append(decoded, g_bytes_get_data(remainder, NULL), g_bytes_get_size(remainder));
        g_bytes_unref(remainder);
    }

    g_assert_cmpmem(encoded->data, encoded->len,
            decoded->data, decoded->len);
}

struct batch_data {
    GByteArray *decoded;
    SfCryptoCipherSession *decoder;
    gint to_decode;
};

static void _tst_crypto_decrypt_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    SfCryptoFixture *fixture = user_data;
    struct batch_data *bd = fixture->test_data;
    GBytes *decrypted;

    (void)source_object;

    sf_crypto_cipher_session_update_finish(res, &decrypted, &fixture->error);

    g_assert_no_error(fixture->error);

    if (g_test_failed()) {
        g_main_loop_quit(fixture->loop);
        return;
    }

    g_byte_array_append(bd->decoded, g_bytes_get_data(decrypted, NULL), g_bytes_get_size(decrypted));
    g_bytes_unref(decrypted);

    if (!--bd->to_decode)
        g_main_loop_quit(fixture->loop);
}

static void _tst_crypto_encrypt_ready(GObject *source_object,
        GAsyncResult *res,
        gpointer user_data)
{
    SfCryptoFixture *fixture = user_data;
    struct batch_data *bd = fixture->test_data;
    GBytes *encrypted;

    (void)source_object;

    sf_crypto_cipher_session_update_finish(res, &encrypted, &fixture->error);

    g_assert_no_error(fixture->error);

    if (g_test_failed()) {
        g_main_loop_quit(fixture->loop);
        return;
    }

    sf_crypto_cipher_session_update(bd->decoder,
            encrypted,
            NULL,
            NULL,
            _tst_crypto_decrypt_ready,
            fixture);
    g_bytes_unref(encrypted);
}

static void tst_crypto_encrypt_decrypt_session_batch(SfCryptoFixture *fixture,
        gconstpointer data)
{
    const struct key_details *kd = data;
    SfCryptoKey *key = g_object_new(SF_TYPE_CRYPTO_KEY,
            "algorithm", kd->algorithm,
            "key-size", kd->key_size,
            NULL);
    SfCryptoCipherSession *encoder;
    gint8 *buffer;
    GBytes *iv;
    GBytes *remainder;
    gsize i;
    GByteArray *encoded;
    struct batch_data bd;

    bd.to_decode = kd->chunks;
    fixture->test_data = &bd;

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

    sf_crypto_cipher_session_new(fixture->manager,
            iv,
            key,
            SF_CRYPTO_OPERATION_ENCRYPT,
            kd->block_mode,
            kd->padding,
            SF_CRYPTO_SIGNATURE_PADDING_NONE,
            SF_CRYPTO_DIGEST_SHA256,
            NULL,
            CRYPTO_PLUGIN_TEST,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    encoder = sf_crypto_cipher_session_new_finish(fixture->test_res, &fixture->error);

    g_assert_no_error(fixture->error);
    g_assert_nonnull(encoder);

    if (g_test_failed())
        return;

    g_test_queue_unref(encoder);

    sf_crypto_cipher_session_new(fixture->manager,
            iv,
            key,
            SF_CRYPTO_OPERATION_DECRYPT,
            kd->block_mode,
            kd->padding,
            SF_CRYPTO_SIGNATURE_PADDING_NONE,
            SF_CRYPTO_DIGEST_SHA256,
            NULL,
            CRYPTO_PLUGIN_TEST,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    bd.decoder = sf_crypto_cipher_session_new_finish(fixture->test_res, &fixture->error);

    g_assert_no_error(fixture->error);
    g_assert_nonnull(bd.decoder);

    if (g_test_failed())
        return;

    g_test_queue_unref(bd.decoder);

    encoded = g_byte_array_sized_new(kd->data_size * kd->chunks);
    bd.decoded = g_byte_array_sized_new(kd->data_size * kd->chunks);

    g_test_queue_destroy((GDestroyNotify)g_byte_array_unref, encoded);
    g_test_queue_destroy((GDestroyNotify)g_byte_array_unref, bd.decoded);

    for (i = 0; i < kd->chunks; i++) {
        GBytes *random_bytes;
        size_t j;

        for (j = 0; j < kd->data_size; j++)
            buffer[j] = g_test_rand_int_range(0, G_MAXUINT8);

        random_bytes = g_bytes_new_static(buffer, kd->data_size);

        g_byte_array_append(encoded, g_bytes_get_data(random_bytes, NULL), g_bytes_get_size(random_bytes));

        sf_crypto_cipher_session_update(encoder,
                random_bytes,
                NULL,
                NULL,
                _tst_crypto_encrypt_ready,
                fixture);
        g_bytes_unref(random_bytes);
    }
    g_main_loop_run(fixture->loop);

    sf_crypto_cipher_session_close(encoder,
            NULL,
            NULL,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    sf_crypto_cipher_session_close_finish(fixture->test_res, &remainder, NULL, &fixture->error);

    g_assert_no_error(fixture->error);

    if (g_test_failed())
        return;

    if (remainder && g_bytes_get_size(remainder)) {
        sf_crypto_cipher_session_update(bd.decoder,
                remainder,
                NULL,
                NULL,
                _tst_crypto_ref_res_and_quit,
                fixture);
        g_bytes_unref(remainder);
        g_main_loop_run(fixture->loop);

        sf_crypto_cipher_session_update_finish(fixture->test_res, &remainder, &fixture->error);

        g_assert_no_error(fixture->error);
        g_assert_nonnull(remainder);

        if (g_test_failed())
            return;

        g_byte_array_append(bd.decoded, g_bytes_get_data(remainder, NULL), g_bytes_get_size(remainder));
    }
    if (remainder)
        g_bytes_unref(remainder);

    sf_crypto_cipher_session_close(bd.decoder,
            NULL,
            NULL,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    sf_crypto_cipher_session_close_finish(fixture->test_res, &remainder, NULL, &fixture->error);

    g_assert_no_error(fixture->error);

    if (g_test_failed())
        return;

    if (remainder) {
        g_byte_array_append(bd.decoded, g_bytes_get_data(remainder, NULL), g_bytes_get_size(remainder));
        g_bytes_unref(remainder);
    }

    g_assert_cmpmem(encoded->data, encoded->len,
            bd.decoded->data, bd.decoded->len);
}

static void tst_crypto_session_sign_verify(SfCryptoFixture *fixture,
        gconstpointer data)
{
    const struct key_details *kd = data;
    SfCryptoKey *key = g_object_new(SF_TYPE_CRYPTO_KEY,
            "algorithm", kd->algorithm,
            "key-size", kd->key_size,
            NULL);
    SfCryptoCipherSession *signer;
    SfCryptoCipherSession *verifier;
    gint8 *buffer;
    GBytes *iv;
    GBytes *signature;
    gsize i;
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

    sf_crypto_cipher_session_new(fixture->manager,
            iv,
            key,
            SF_CRYPTO_OPERATION_SIGN,
            kd->block_mode,
            kd->padding,
            SF_CRYPTO_SIGNATURE_PADDING_NONE,
            SF_CRYPTO_DIGEST_SHA256,
            NULL,
            CRYPTO_PLUGIN_TEST,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    signer = sf_crypto_cipher_session_new_finish(fixture->test_res, &fixture->error);

    g_assert_no_error(fixture->error);
    g_assert_nonnull(signer);

    if (g_test_failed())
        return;

    g_test_queue_unref(signer);

    sf_crypto_cipher_session_new(fixture->manager,
            iv,
            key,
            SF_CRYPTO_OPERATION_VERIFY,
            kd->block_mode,
            kd->padding,
            SF_CRYPTO_SIGNATURE_PADDING_NONE,
            SF_CRYPTO_DIGEST_SHA256,
            NULL,
            CRYPTO_PLUGIN_TEST,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    verifier = sf_crypto_cipher_session_new_finish(fixture->test_res, &fixture->error);

    g_assert_no_error(fixture->error);
    g_assert_nonnull(verifier);

    if (g_test_failed())
        return;

    g_test_queue_unref(verifier);

    for (i = 0; i < kd->chunks; i++) {
        GBytes *random_bytes;

        sf_crypto_manager_generate_random_data(fixture->manager,
                kd->data_size,
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

        sf_crypto_cipher_session_update(signer,
                random_bytes,
                NULL,
                NULL,
                _tst_crypto_ref_res_and_quit,
                fixture);
        g_main_loop_run(fixture->loop);

        sf_crypto_cipher_session_update_finish(fixture->test_res, NULL, &fixture->error);

        g_assert_no_error(fixture->error);

        if (g_test_failed())
            return;

        if (kd->fuzz_data)
            random_bytes = _fuzz_bytes_take(random_bytes, kd->fuzz_data);

        sf_crypto_cipher_session_update(verifier,
                random_bytes,
                NULL,
                NULL,
                _tst_crypto_ref_res_and_quit,
                fixture);
        g_bytes_unref(random_bytes);
        g_main_loop_run(fixture->loop);

        sf_crypto_cipher_session_update_finish(fixture->test_res, NULL, &fixture->error);

        g_assert_no_error(fixture->error);

        if (g_test_failed())
            return;
    }

    sf_crypto_cipher_session_close(signer,
            NULL,
            NULL,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);

    sf_crypto_cipher_session_close_finish(fixture->test_res, &signature, NULL, &fixture->error);

    g_assert_no_error(fixture->error);
    g_assert_nonnull(signature);

    if (g_test_failed())
        return;

    if (kd->fuzz_sig)
        signature = _fuzz_bytes_take(signature, kd->fuzz_sig);

    sf_crypto_cipher_session_close(verifier,
            signature,
            NULL,
            NULL,
            _tst_crypto_ref_res_and_quit,
            fixture);
    g_main_loop_run(fixture->loop);
    g_bytes_unref(signature);

    sf_crypto_cipher_session_close_finish(fixture->test_res,
            NULL,
            &verify_status,
            &fixture->error);

    g_assert_no_error(fixture->error);

    if (g_test_failed())
        return;

    g_assert_cmpint(verify_status, ==, kd->expected_status);
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
    sf_secret_test("SetSecretNoCollection", tst_secret_set_no_collection);
    sf_secret_test("SetSecretStandaloneWithCollection", tst_secret_set_standalone_with_collection);
    sf_secret_test("SetGetStandaloneSecret", tst_secret_set_get_standalone_secret);
    sf_secret_test("SetGetCollectionSecret", tst_secret_set_get_collection_secret);
    sf_secret_test("SetFindDeleteCollectionSecret", tst_secret_set_find_delete_collection_secret);
    sf_secret_test("GetFromNonexistentPlugin", tst_secret_collections_nonexistent_plugin);
    sf_secret_test("GetFromNonexistentCollection", tst_secret_get_from_nonexistent_collection);
    sf_secret_test("CreateExistingCollection", tst_secret_create_existing_collection);
    sf_secret_test("InteractionRequest", tst_secret_interaction_request);
#undef sf_secret_test

#define sf_crypto_test(name, test, data) \
    g_test_add("/Crypto/" name, SfCryptoFixture, data, \
            tst_crypto_setup, test, tst_crypto_teardown)
    sf_crypto_test("CreateManager", tst_crypto_create_manager, NULL);
    sf_crypto_test("GetPluginInfo", tst_crypto_get_plugin_info, NULL);
    sf_crypto_test("GenerateRandomData", tst_crypto_generate_random_data, NULL);
    sf_crypto_test("GenerateKey", tst_crypto_generate_key, NULL);
    sf_crypto_test("NonexistentStoredKey", tst_crypto_nonexistent_stored_key, NULL);
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
        .data_size = 256,
        .expected_status = SF_CRYPTO_VERIFICATION_STATUS_SUCCEEDED }));
    sf_crypto_test("SignVerifyFuzzSigRsa2048", tst_crypto_sign_verify, (&(struct key_details){
        .algorithm = SF_CRYPTO_ALGORITHM_RSA,
        .padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
        .block_mode = SF_CRYPTO_BLOCK_MODE_UNKNOWN,
        .key_size = 2048,
        .data_size = 256,
        .fuzz_sig = 1,
        .expected_status = SF_CRYPTO_VERIFICATION_STATUS_FAILED }));
    sf_crypto_test("SignVerifyFuzzDataRsa2048", tst_crypto_sign_verify, (&(struct key_details){
        .algorithm = SF_CRYPTO_ALGORITHM_RSA,
        .padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
        .block_mode = SF_CRYPTO_BLOCK_MODE_UNKNOWN,
        .key_size = 2048,
        .data_size = 256,
        .fuzz_data = 1,
        .expected_status = SF_CRYPTO_VERIFICATION_STATUS_FAILED }));
    sf_crypto_test("ImportVerify", tst_crypto_import_verify, NULL);
    sf_crypto_test("ImportInvalid", tst_crypto_import_invalid, NULL);
    sf_crypto_test("EncryptDecryptSessionAes128", tst_crypto_encrypt_decrypt_session, (&(struct key_details){
        .algorithm = SF_CRYPTO_ALGORITHM_AES,
        .padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
        .block_mode = SF_CRYPTO_BLOCK_MODE_CBC,
        .key_size = 128,
        .chunks = 5,
        .data_size = 1024 }));
    sf_crypto_test("EncryptDecryptSessionBatchAes128", tst_crypto_encrypt_decrypt_session_batch, (&(struct key_details){
        .algorithm = SF_CRYPTO_ALGORITHM_AES,
        .padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
        .block_mode = SF_CRYPTO_BLOCK_MODE_CBC,
        .key_size = 128,
        .chunks = 5,
        .data_size = 1024 }));
    sf_crypto_test("SignVerifySessionRsa2048", tst_crypto_session_sign_verify, (&(struct key_details){
        .algorithm = SF_CRYPTO_ALGORITHM_RSA,
        .padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
        .block_mode = SF_CRYPTO_BLOCK_MODE_UNKNOWN,
        .key_size = 2048,
        .chunks = 5,
        .data_size = 256,
        .expected_status = SF_CRYPTO_VERIFICATION_STATUS_SUCCEEDED }));
    sf_crypto_test("SignVerifySessionFuzzDataRsa2048", tst_crypto_session_sign_verify, (&(struct key_details){
        .algorithm = SF_CRYPTO_ALGORITHM_RSA,
        .padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
        .block_mode = SF_CRYPTO_BLOCK_MODE_UNKNOWN,
        .key_size = 2048,
        .chunks = 5,
        .data_size = 256,
        .fuzz_data = 1,
        .expected_status = SF_CRYPTO_VERIFICATION_STATUS_FAILED }));
    sf_crypto_test("SignVerifySessionFuzzSigRsa2048", tst_crypto_session_sign_verify, (&(struct key_details){
        .algorithm = SF_CRYPTO_ALGORITHM_RSA,
        .padding = SF_CRYPTO_ENCRYPTION_PADDING_NONE,
        .block_mode = SF_CRYPTO_BLOCK_MODE_UNKNOWN,
        .key_size = 2048,
        .chunks = 5,
        .data_size = 256,
        .fuzz_sig = 1,
        .expected_status = SF_CRYPTO_VERIFICATION_STATUS_FAILED }));
#undef sf_secret_test

    g_test_run();

    return 0;
}
