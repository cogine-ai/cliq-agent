#ifndef CLIQ_HTTP_OWNER_MECHANISM_H
#define CLIQ_HTTP_OWNER_MECHANISM_H
/* Private selected-image implementation, included after its local owner layout.
 * This is the original model TLS/Secret Service/NoEcho mechanism unchanged for
 * that image. The MCP image supplies its own closed recipe and authority FSM;
 * no model/dependency exports or accepted response guards are broadened. */
static bool digest_hex(const unsigned char *bytes, size_t size, char result[65]) {
  unsigned char digest[32];
  if (!SHA256(bytes, size, digest)) { wipe(digest, sizeof(digest)); return false; }
  for (size_t index = 0; index < 32; index++) snprintf(result + index * 2, 3, "%02x", digest[index]);
  wipe(digest, sizeof(digest)); return true;
}
static bool broker_digest(napi_env env, napi_value value, const char *field, char output[65]) {
  return field_text(env, value, field, output, 65) && strlen(output) == 64 && strspn(output, "0123456789abcdef") == 64;
}
static bool broker_integer(napi_env env, napi_value value, const char *field, uint64_t minimum, uint64_t *output) {
  napi_value member_value; double number;
  if (!member(env, value, field, &member_value) || napi_get_value_double(env, member_value, &number) != napi_ok ||
      !isfinite(number) || number < minimum || number > 9007199254740991.0 || number != (uint64_t)number) return false;
  *output = (uint64_t)number; return true;
}
static bool broker_buffer(napi_env env, napi_value value, const char *field, size_t maximum,
  unsigned char **output, size_t *size) {
  napi_value property; bool buffer; void *bytes;
  if (!member(env, value, field, &property) || napi_is_buffer(env, property, &buffer) != napi_ok || !buffer ||
      napi_get_buffer_info(env, property, &bytes, size) != napi_ok || !*size || *size > maximum) return false;
  *output = malloc(*size);
  if (!*output) return false;
  memcpy(*output, bytes, *size); return true;
}
static bool broker_host(const char *value) {
  size_t length = strlen(value);
  if (!length || length > 253 || value[0] == '.' || value[length - 1] == '.' ||
      strspn(value, "abcdefghijklmnopqrstuvwxyz0123456789.-") != length) return false;
  const char *label = value;
  while (*label) {
    const char *end = strchr(label, '.'); size_t count = end ? (size_t)(end - label) : strlen(label);
    if (!count || count > 63 || label[0] == '-' || label[count - 1] == '-') return false;
    if (!end) break;
    label = end + 1;
  }
  return true;
}
static bool broker_path(const char *value) {
  if (value[0] != '/' || strchr(value, '?') || strchr(value, '#') || strchr(value, '\\') ||
      strchr(value, '%') || strspn(value, "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-+") != strlen(value)) return false;
  const char *cursor = value + 1;
  while (*cursor) {
    const char *end = strchr(cursor, '/'); size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
    if (!length || (length == 1 && cursor[0] == '.') || (length == 2 && !memcmp(cursor, "..", 2))) return false;
    if (!end) return true;
    cursor = end + 1;
  }
  return true;
}
static bool broker_live(struct broker *broker) {
  return (!atomic_load(&broker->cancelled) && !atomic_load(&retirement_failed) && remaining(&broker->platform) > 0) ||
    broker_fail(broker, "broker_cancelled_or_expired");
}
static bool broker_platform_retire(struct broker *broker) {
  struct task *task = &broker->platform;
  if (task->bus) {
    GError *error = NULL;
    if (!g_dbus_connection_is_closed(task->bus) && !g_dbus_connection_close_sync(task->bus, NULL, &error)) {
      task->unsafe = true; atomic_store(&retirement_failed, true); fail(task, "resource_retirement");
    }
    g_clear_error(&error);
    if (!task->unsafe) { g_object_unref(task->bus); task->bus = NULL; }
  }
  if (!retired_close(task, &task->runtime_fd)) task->unsafe = true;
  if (task->unsafe) { broker->unsafe = true; return broker_fail(broker, "resource_retirement"); }
  return true;
}
static bool broker_read_key(struct broker *broker) {
  struct task *task = &broker->platform; bool found = false;
  if (!connect_bus(task) || !observe_owner(task, SECRET_NAME, &task->observed.service) || !default_collection(task) ||
      !search_item(task, &found) || !found || !verify_item(task) || !expected_platform(task) || !open_session(task))
    return broker_fail(broker, "credential_redemption_refused");
  GVariant *reply = call(task, task->observed.service.unique, task->observed.item, SECRET_INTERFACE "Item", "GetSecret",
    g_variant_new("(o)", task->session), "((oayays))");
  if (!reply) return broker_fail(broker, "credential_redemption_refused");
  GVariant *parameters, *bytes; const char *session, *content_type;
  g_variant_get(reply, "((&o@ay@ay&s))", &session, &parameters, &bytes, &content_type);
  gsize size = 0; const unsigned char *secret = g_variant_get_fixed_array(bytes, &size, 1);
  bool valid = !strcmp(session, task->session) && !g_variant_n_children(parameters) && size > 0 && size <= MAX_SECRET &&
    (!strcmp(content_type, "application/octet-stream") || !strcmp(content_type, "text/plain"));
  for (size_t index = 0; valid && index < size; index++) valid = secret[index] >= 0x21 && secret[index] <= 0x7e;
  static const char *const protocol_literals[] = {"{", "}", "[", "]", "\"", ":", "application/json"};
  for (size_t index = 0; valid && index < sizeof(protocol_literals) / sizeof(protocol_literals[0]); index++) {
    const char *literal = protocol_literals[index];
    if (memmem(literal, strlen(literal), secret, size) != NULL) valid = false;
  }
  if (valid) {
    task->secret = malloc(size);
    valid = task->secret != NULL;
    if (valid) { memcpy(task->secret, secret, size); task->secret_size = size; }
  }
  /* Secret Service's immutable reply storage is never exported or persisted.
   * Only our owned copy survives the immediate reply retirement. */
  g_variant_unref(parameters); g_variant_unref(bytes); g_variant_unref(reply);
  if (!valid || !verify_item(task) || !default_collection(task) || !observe_owner(task, SECRET_NAME, &task->observed.service) ||
      !expected_platform(task) || !bus_current(task)) return broker_fail(broker, "credential_redemption_refused");
  return broker_live(broker);
}
static bool broker_tls_wait(struct broker *broker, int error) {
  if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return broker_fail(broker, "broker_transport_interrupted");
  if (!broker_live(broker)) return false;
  struct pollfd descriptor = { .fd = g_socket_get_fd(broker->socket), .events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT };
  int result;
  do { result = poll(&descriptor, 1, 50); } while (result < 0 && errno == EINTR && broker_live(broker));
  return (result >= 0 || broker_fail(broker, "broker_transport_interrupted")) && broker_live(broker);
}
static bool broker_load_ca(struct broker *broker) {
  broker->tls_context = SSL_CTX_new(TLS_client_method());
  if (!broker->tls_context || !SSL_CTX_set_min_proto_version(broker->tls_context, TLS1_3_VERSION) ||
      !SSL_CTX_set_max_proto_version(broker->tls_context, TLS1_3_VERSION)) return broker_fail(broker, "broker_tls_refused");
  SSL_CTX_set_verify(broker->tls_context, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_options(broker->tls_context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  BIO *input = BIO_new_mem_buf(broker->trust, (int)broker->trust_size);
  if (!input) return broker_fail(broker, "broker_tls_refused");
  unsigned count = 0; X509 *certificate;
  while ((certificate = PEM_read_bio_X509(input, NULL, NULL, NULL))) {
    bool added = X509_STORE_add_cert(SSL_CTX_get_cert_store(broker->tls_context), certificate) == 1;
    X509_free(certificate);
    if (!added || ++count > 4096) { BIO_free(input); ERR_clear_error(); return broker_fail(broker, "broker_tls_refused"); }
  }
  BIO_free(input); ERR_clear_error();
  return count > 0 || broker_fail(broker, "broker_tls_refused");
}
static bool broker_pin(struct broker *broker) {
  X509 *certificate = SSL_get1_peer_certificate(broker->tls);
  if (!certificate) return broker_fail(broker, "broker_tls_refused");
  X509_PUBKEY *key = X509_get_X509_PUBKEY(certificate); unsigned char *encoded = NULL;
  int count = i2d_X509_PUBKEY(key, &encoded); unsigned char digest[32];
  bool valid = count > 0 && encoded != NULL && SHA256(encoded, (size_t)count, digest) != NULL, matched = false;
  for (size_t index = 0; valid && index < broker->pin_count; index++) matched |= CRYPTO_memcmp(digest, broker->pins[index], 32) == 0;
  wipe(digest, sizeof(digest)); OPENSSL_free(encoded); X509_free(certificate);
  return (valid && matched) || broker_fail(broker, "broker_tls_refused");
}
static bool broker_connect(struct broker *broker) {
#if defined(CLIQ_MCP_HTTP_BROKER_MODULE)
  /* GSocketClient can walk multiple resolved addresses. This fixed MCP
   * profile authorizes one CONNECT attempt only; DNS returns candidates but
   * only the original first address is ever used, without fallback. */
  GError *error = NULL; GResolver *resolver = g_resolver_get_default();
  GList *addresses = g_resolver_lookup_by_name(resolver, broker->host, broker->platform.cancel, &error);
  g_object_unref(resolver); g_clear_error(&error);
  if (!addresses || !broker_live(broker)) { if (addresses) g_resolver_free_addresses(addresses); return broker_fail(broker, "broker_transport_interrupted"); }
  GInetAddress *chosen = addresses->data;
  GSocket *socket = g_socket_new(g_inet_address_get_family(chosen), G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, &error);
  GSocketAddress *address = socket ? g_inet_socket_address_new(chosen, (guint16)broker->port) : NULL;
  g_resolver_free_addresses(addresses); g_clear_error(&error);
  if (!socket || !address) { if (socket) g_object_unref(socket); if (address) g_object_unref(address); return broker_fail(broker, "broker_transport_interrupted"); }
  broker->connection = g_socket_connection_factory_create_connection(socket); g_object_unref(socket);
  if (!broker->connection) { g_object_unref(address); return broker_fail(broker, "broker_transport_interrupted"); }
  broker->socket = g_socket_connection_get_socket(broker->connection);
  g_socket_set_timeout(broker->socket, DEADLINE_SECONDS);
  bool connected = g_socket_connect(broker->socket, address, broker->platform.cancel, &error);
  g_object_unref(address); g_clear_error(&error);
  if (!connected || !broker_live(broker)) return broker_fail(broker, "broker_transport_interrupted");
#else
  GSocketClient *client = g_socket_client_new();
  g_socket_client_set_enable_proxy(client, FALSE);
  g_socket_client_set_tls(client, FALSE);
  g_socket_client_set_timeout(client, DEADLINE_SECONDS);
  GError *error = NULL;
  broker->connection = g_socket_client_connect_to_host(client, broker->host, (guint16)broker->port, broker->platform.cancel, &error);
  g_object_unref(client); g_clear_error(&error);
  if (!broker->connection || !broker_live(broker)) return broker_fail(broker, "broker_transport_interrupted");
  broker->socket = g_socket_connection_get_socket(broker->connection);
#endif
  g_socket_set_blocking(broker->socket, FALSE);
  if (!broker_load_ca(broker)) return false;
  broker->tls = SSL_new(broker->tls_context);
  if (!broker->tls || !SSL_set_fd(broker->tls, g_socket_get_fd(broker->socket)) ||
      !SSL_set_tlsext_host_name(broker->tls, broker->server_name)) return broker_fail(broker, "broker_tls_refused");
  X509_VERIFY_PARAM *parameters = SSL_get0_param(broker->tls);
  X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
  if (g_hostname_is_ip_address(broker->server_name)) {
    if (!X509_VERIFY_PARAM_set1_ip_asc(parameters, broker->server_name)) return broker_fail(broker, "broker_tls_refused");
  } else if (!SSL_set1_host(broker->tls, broker->server_name)) return broker_fail(broker, "broker_tls_refused");
  for (;;) {
    if (!broker_live(broker)) return false;
    int result = SSL_connect(broker->tls);
    if (result == 1) break;
    if (!broker_tls_wait(broker, SSL_get_error(broker->tls, result))) return false;
  }
  if (SSL_version(broker->tls) != TLS1_3_VERSION || SSL_get_verify_result(broker->tls) != X509_V_OK || !broker_pin(broker))
    return broker_fail(broker, "broker_tls_refused");
  /* Ready means native platform identities remained original after the slow
   * handshake. Root still supplies the final fresh SQL/credential release cut. */
  struct task *task = &broker->platform;
#if defined(CLIQ_MCP_HTTP_BROKER_MODULE)
  if (!broker->credential_present) return broker_live(broker);
#endif
  return verify_item(task) && default_collection(task) && observe_owner(task, SECRET_NAME, &task->observed.service) &&
    expected_platform(task) && bus_current(task) && broker_live(broker);
}
static bool broker_write(struct broker *broker, const unsigned char *bytes, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    if (!broker_live(broker)) return false;
    size_t written = 0; int result = SSL_write_ex(broker->tls, bytes + offset, size - offset, &written);
    if (result == 1) { if (!written) return broker_fail(broker, "broker_transport_interrupted"); offset += written; }
    else if (!broker_tls_wait(broker, SSL_get_error(broker->tls, result))) return false;
  }
  return true;
}
/* Reads are never retried as requests. A short/failed response remains an
 * ambiguous transport outcome after release, not a no-effect assertion. */
static ssize_t broker_read(struct broker *broker, unsigned char *bytes, size_t size) {
  for (;;) {
    if (!broker_live(broker)) return -1;
    size_t received = 0; int result = SSL_read_ex(broker->tls, bytes, size, &received);
    if (result == 1) return received ? (ssize_t)received : -1;
    int error = SSL_get_error(broker->tls, result);
    if (error == SSL_ERROR_ZERO_RETURN) return 0;
    if (!broker_tls_wait(broker, error)) return -1;
  }
}
static bool broker_line(struct broker *broker, char *line, size_t capacity, size_t *total) {
  size_t length = 0;
  while (length + 1 < capacity) {
    unsigned char byte;
    if (broker_read(broker, &byte, 1) != 1 || ++*total > BROKER_HEADER_CAP) return broker_fail(broker, "broker_response_refused");
    if (byte == '\r') {
      if (broker_read(broker, &byte, 1) != 1 || ++*total > BROKER_HEADER_CAP || byte != '\n')
        return broker_fail(broker, "broker_response_refused");
      line[length] = '\0'; return true;
    }
    if (byte == '\n' || byte == 0 || (byte < 0x20 && byte != '\t') || byte > 0x7e) return broker_fail(broker, "broker_response_refused");
    line[length++] = (char)byte;
  }
  return broker_fail(broker, "broker_response_refused");
}
#include "no-echo-bytes-mechanism.h"

#endif

