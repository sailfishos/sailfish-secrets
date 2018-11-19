#ifndef SF_SECRETS_SECRET_H
#define SF_SECRETS_SECRET_H

#include <glib-object.h>

#define SF_TYPE_SECRETS_SECRET (sf_secrets_secret_get_type())
#define SF_SECRETS_SECRET(o) (G_TYPE_CHECK_INSTANCE_CAST((o), SF_TYPE_SECRETS_SECRET, SfSecretsSecret))
#define SF_IS_SECRETS_SECRET(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), SF_TYPE_SECRETS_SECRET))

typedef struct SfSecretsSecret_ SfSecretsSecret;
typedef struct SfSecretsSecretClass_ SfSecretsSecretClass;
typedef enum SfSecretsSecretFlags_ SfSecretsSecretFlags;

struct SfSecretsSecret_ {
	GInitiallyUnowned parent;
};

struct SfSecretsSecretClass_ {
	GInitiallyUnownedClass parent_class;
};

GType sf_secrets_secret_get_type(void);
SfSecretsSecret *sf_secrets_secret_new(const gchar *identifier);
SfSecretsSecret *sf_secrets_secret_new_data(const gchar *identifier, GBytes *data);

void sf_secrets_secret_set_filter_field(SfSecretsSecret *secret, const gchar *key, const gchar *value);
const gchar *sf_secrets_secret_get_filter_field(SfSecretsSecret *secret, const gchar *key);

#endif /* SF_SECRETS_SECRET_H */
