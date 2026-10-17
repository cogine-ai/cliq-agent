/* Fixed test-only Secret Service data protocol shared by two actual external
 * services. No bus ownership, process creation, authority, timing or control
 * phase lives here; each fixture owns those independently. */
#ifndef CLIQ_TEST_SECRET_SERVICE_FIXTURE_H
#define CLIQ_TEST_SECRET_SERVICE_FIXTURE_H
#include <gio/gio.h>
#include <stdbool.h>
#include <string.h>
#define SECRET_ROOT "/org/freedesktop/secrets"
#define SECRET_COLLECTION SECRET_ROOT "/collection/component"
#define SECRET_ITEM SECRET_COLLECTION "/item"
#define SECRET_SESSION SECRET_ROOT "/session/component"
struct fixture_secret_data { bool created; GVariant *item_attributes, *item_secret; };
static bool fixture_secret_method(struct fixture_secret_data *secret, const char *interface, const char *method,
  GVariant *parameters, GDBusMethodInvocation *invocation) {
  if (!strcmp(interface, "org.freedesktop.Secret.Service") && !strcmp(method, "SearchItems")) {
    GVariant *attributes = g_variant_get_child_value(parameters, 0);
    bool valid = g_variant_n_children(attributes) == 9 && (!secret->created || g_variant_equal(attributes, secret->item_attributes));
    g_variant_unref(attributes); if (!valid) return false;
    const char *items[] = {SECRET_ITEM, NULL}, *empty[] = {NULL};
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(@ao@ao)",
      g_variant_new_objv(secret->created ? items : empty, -1), g_variant_new_objv(empty, -1))); return true;
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Service") && !strcmp(method, "OpenSession")) {
    const char *algorithm; GVariant *box; g_variant_get(parameters, "(&s@v)", &algorithm, &box);
    GVariant *value = g_variant_get_variant(box); bool valid = !strcmp(algorithm, "plain") &&
      g_variant_is_of_type(value, G_VARIANT_TYPE_STRING) && !g_variant_get_string(value, NULL)[0];
    g_variant_unref(value); g_variant_unref(box); if (!valid) return false;
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(vo)", g_variant_new_string(""), SECRET_SESSION)); return true;
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Collection") && !strcmp(method, "CreateItem") && !secret->created) {
    GVariant *properties = g_variant_get_child_value(parameters, 0), *envelope = g_variant_get_child_value(parameters, 1);
    secret->item_attributes = g_variant_lookup_value(properties, "org.freedesktop.Secret.Item.Attributes", G_VARIANT_TYPE("a{ss}"));
    secret->item_secret = g_variant_get_child_value(envelope, 2);
    bool valid = secret->item_attributes && g_variant_n_children(secret->item_attributes) == 9 &&
      g_variant_n_children(secret->item_secret) > 0 && g_variant_n_children(secret->item_secret) <= 256;
    g_variant_unref(properties); g_variant_unref(envelope); if (!valid) return false;
    secret->created = true;
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(oo)", SECRET_ITEM, "/")); return true;
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Item") && !strcmp(method, "GetSecret") && secret->created) {
    const char *session; g_variant_get(parameters, "(&o)", &session); if (strcmp(session, SECRET_SESSION)) return false;
    g_dbus_method_invocation_return_value(invocation, g_variant_new("((o@ay@ays))", SECRET_SESSION,
      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, 1), g_variant_ref(secret->item_secret), "application/octet-stream")); return true;
  }
  return false;
}
static GVariant *fixture_secret_property(struct fixture_secret_data *secret, const char *interface, const char *property) {
  if (!strcmp(interface, "org.freedesktop.Secret.Service") && !strcmp(property, "Collections")) {
    const char *collections[] = {SECRET_COLLECTION, NULL}; return g_variant_new_objv(collections, -1);
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Collection") && !strcmp(property, "Items")) {
    const char *items[] = {SECRET_ITEM, NULL}, *empty[] = {NULL}; return g_variant_new_objv(secret->created ? items : empty, -1);
  }
  if ((!strcmp(interface, "org.freedesktop.Secret.Collection") || !strcmp(interface, "org.freedesktop.Secret.Item")) &&
      !strcmp(property, "Locked")) return g_variant_new_boolean(FALSE);
  if (!strcmp(interface, "org.freedesktop.Secret.Item") && !strcmp(property, "Attributes") && secret->item_attributes)
    return g_variant_ref(secret->item_attributes);
  return NULL;
}
static void fixture_secret_clear(struct fixture_secret_data *secret) {
  if (secret->item_attributes) g_variant_unref(secret->item_attributes);
  if (secret->item_secret) g_variant_unref(secret->item_secret);
  memset(secret, 0, sizeof(*secret));
}
#endif
