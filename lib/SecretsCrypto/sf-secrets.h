#ifndef SF_SECRETS_H
#define SF_SECRETS_H

#include <glib-object.h>
#include <gio/gio.h>

#define SF_TYPE_SECRETS_PLUGIN_INFO (sf_secrets_manager_get_type())

typedef struct SfSecretsPluginInfo_ SfSecretsPluginInfo;
typedef struct SfSecretsSecret_ SfSecretsSecret;
typedef struct SfSecretsSecretIdentifier_ SfSecretsSecretIdentifier;

typedef enum SfSecretsUserInteractionMode_ {
	SF_SECRETS_USER_INTERACTION_MODE_PREVENT = 0,
	SF_SECRETS_USER_INTERACTION_MODE_SYSTEM,
	SF_SECRETS_USER_INTERACTION_MODE_APPLICATION
} SfSecretsUserInteractionMode;

typedef enum SfSecretsAccessControlMode_ {
	SF_SECRETS_ACCESS_CONTROL_OWNER_ONLY = 0,
	SF_SECRETS_ACCESS_CONTROL_SYSTEM_ACCESS,
	SF_SECRETS_ACCESS_CONTROL_NONE
} SfSecretsAccessControlMode;

typedef enum SfSecretsPluginState_ {
	SF_SECRETS_PLUGIN_STATE_UNKNOWN   = 0,
	SF_SECRETS_PLUGIN_STATE_AVAILABLE = 1 << 0,
	SF_SECRETS_PLUGIN_STATE_MASTER_UNLOCKED = 1 << 1,
	SF_SECRETS_PLUGIN_STATE_PLUGIN_UNLOCKED = 1 << 2,
	SF_SECRETS_PLUGIN_STATE_PLUGIN_SUPPORTS_LOCKING = 1 << 2,
	SF_SECRETS_PLUGIN_STATE_PLUGIN_SUPPORTS_SET_LOCK_CODE = 1 << 2,
} SfSecretsPluginState;

struct SfSecretsPluginInfo_ {
	gchar *display_name;
	gchar *name;
	int version;
	SfSecretsPluginState state;
};

struct SfSecretsSecretIdentifier_ {
	gchar *name;
	gchar *collection_name;
	gchar *storage_plugin_name;
};

struct SfSecretsSecret_ {
	SfSecretsSecretIdentifier *identifier;
	GHashTable *filters;
	GBytes *data;
};

void sf_secrets_plugin_info_free(SfSecretsPluginInfo *info);

#endif
