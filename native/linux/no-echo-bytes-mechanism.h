#ifndef CLIQ_NO_ECHO_BYTES_MECHANISM_H
#define CLIQ_NO_ECHO_BYTES_MECHANISM_H
/* Original finite byte/projection screen shared by selected native owners.
 * Include after the local owner, broker_live and broker_fail definitions. */
static bool broker_contains(const unsigned char *bytes, size_t size, const unsigned char *needle, size_t needle_size) {
  return needle_size && size >= needle_size && memmem(bytes, size, needle, needle_size) != NULL;
}
static bool broker_no_echo_plain(struct broker *broker, const unsigned char *bytes, size_t size) {
  const unsigned char *secret = broker->platform.secret; size_t count = broker->platform.secret_size;
  if (broker_contains(bytes, size, secret, count)) return broker_fail(broker, "broker_response_refused");
  gchar *base64 = g_base64_encode(secret, count);
  bool echoed = base64 && broker_contains(bytes, size, (const unsigned char *)base64, strlen(base64));
  if (base64 && !echoed) {
    size_t length = strlen(base64);
    for (size_t index = 0; index < length; index++) {
      if (base64[index] == '+') base64[index] = '-';
      else if (base64[index] == '/') base64[index] = '_';
    }
    while (length && base64[length - 1] == '=') length--;
    echoed = broker_contains(bytes, size, (const unsigned char *)base64, length);
  }
  if (base64) { wipe(base64, strlen(base64)); g_free(base64); }
  unsigned char *encoded = malloc(count * 2 + 1);
  if (!encoded) return broker_fail(broker, "broker_worker_unavailable");
  if (!echoed) {
    for (size_t index = 0; index < count; index++) snprintf((char *)encoded + index * 2, 3, "%02x", secret[index]);
    echoed = broker_contains(bytes, size, encoded, count * 2);
    for (size_t index = 0; index < count * 2; index++) if (encoded[index] >= 'a' && encoded[index] <= 'f') encoded[index] -= 'a' - 'A';
    echoed |= broker_contains(bytes, size, encoded, count * 2);
  }
  if (!echoed) {
    size_t length = 0;
    for (size_t index = 0; index < count; index++) {
      if (secret[index] == '"' || secret[index] == '\\') encoded[length++] = '\\';
      encoded[length++] = secret[index];
    }
    echoed = broker_contains(bytes, size, encoded, length);
  }
  wipe(encoded, count * 2 + 1); free(encoded);
  if (echoed) return broker_fail(broker, "broker_response_refused");
  return true;
}
static int broker_hex_digit(unsigned char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}
static bool broker_unicode_hex(const unsigned char *bytes, size_t size, size_t at, unsigned *point) {
  if (at >= size || size - at <= 4) return false;
  *point = 0;
  for (size_t digit = 1; digit <= 4; digit++) {
    int value = broker_hex_digit(bytes[at + digit]);
    if (value < 0) return false;
    *point = *point * 16 + (unsigned)value;
  }
  return true;
}
static bool broker_no_echo_normalized(struct broker *broker, const unsigned char *bytes, size_t size) {
  if (!broker_no_echo_plain(broker, bytes, size)) return false;
  /* NUL separates string projections and cannot occur in the Bearer key.
   * Normalize only valid UTF-8 segments; invalid JSON/UTF-8 still belongs to
   * the closed production provider decoder, not this leak screen. */
  for (size_t start = 0; start < size;) {
    size_t end = start; while (end < size && bytes[end]) end++;
    if (end > start && g_utf8_validate((const char *)bytes + start, (gssize)(end - start), NULL)) {
      gchar *normalized = g_utf8_normalize((const char *)bytes + start, (gssize)(end - start), G_NORMALIZE_NFC);
      if (!normalized) return broker_fail(broker, "broker_worker_unavailable");
      size_t count = strlen(normalized); bool valid = broker_no_echo_plain(broker, (const unsigned char *)normalized, count);
      wipe(normalized, count); g_free(normalized); if (!valid) return false;
    }
    start = end + 1;
  }
  return true;
}
#if defined(CLIQ_MCP_HTTP_BROKER_MODULE) || defined(CLIQ_MCP_STDIO_BROKER_MODULE)
static bool broker_no_echo_mode(struct broker *broker, const unsigned char *bytes, size_t size, bool received_bytes) {
#else
static bool broker_no_echo(struct broker *broker, const unsigned char *bytes, size_t size) {
#endif
  /* OpenAI arguments are themselves JSON strings. A single unescape pass
   * would let a later provider/schema parse recover the key in JavaScript.
   * Two bounded native buffers screen up to 64 string-projection layers,
   * including Unicode/NFC, without ever rewriting the original response.
   * This finite guard is not arbitrary malicious-transform confidentiality. */
  unsigned char *first = malloc(size + 1), *second = malloc(size + 1);
  if (!first || !second) { free(first); free(second); return broker_fail(broker, "broker_worker_unavailable"); }
  const unsigned char *current = bytes; size_t current_size = size; bool valid = true;
  for (unsigned depth = 0;; depth++) {
#if defined(CLIQ_MCP_HTTP_BROKER_MODULE) || defined(CLIQ_MCP_STDIO_BROKER_MODULE)
    /* Only immutable spans already owned by the current received-data task use
     * this offline mode. It grants no read, write, release or live authority. */
    if ((!received_bytes && !broker_live(broker)) || !broker_no_echo_normalized(broker, current, current_size)) { valid = false; break; }
#else
    if (!broker_live(broker) || !broker_no_echo_normalized(broker, current, current_size)) { valid = false; break; }
#endif
    unsigned char *decoded = current == first ? second : first;
    size_t count = 0; bool escaped = false;
    for (size_t index = 0; index < current_size; index++) {
      if (current[index] != '"') continue;
      while (++index < current_size && current[index] != '"') {
        unsigned char byte = current[index];
        if (byte == '\\') {
          escaped = true; if (++index == current_size) break;
          byte = current[index];
          if (byte == 'u') {
            unsigned point;
            if (broker_unicode_hex(current, current_size, index, &point)) {
              index += 4;
              if (point >= 0xd800 && point <= 0xdbff) {
                unsigned low;
                if (current_size - index > 6 && current[index + 1] == '\\' && current[index + 2] == 'u' &&
                    broker_unicode_hex(current, current_size, index + 2, &low) && low >= 0xdc00 && low <= 0xdfff) {
                  point = 0x10000 + (point - 0xd800) * 1024 + low - 0xdc00; index += 6;
                }
              }
              if (g_unichar_validate(point)) { count += (size_t)g_unichar_to_utf8(point, (char *)decoded + count); continue; }
            }
            byte = 0;
          } else if (byte == 'b') byte = '\b';
          else if (byte == 'f') byte = '\f';
          else if (byte == 'n') byte = '\n';
          else if (byte == 'r') byte = '\r';
          else if (byte == 't') byte = '\t';
          else if (byte != '"' && byte != '\\' && byte != '/') byte = 0;
        }
        decoded[count++] = byte;
      }
      decoded[count++] = 0;
    }
    if (!escaped) break;
    if (depth == 64) { valid = broker_fail(broker, "broker_response_refused"); break; }
    current = decoded; current_size = count;
  }
  wipe(first, size + 1); wipe(second, size + 1); free(first); free(second); return valid;
}
#if defined(CLIQ_MCP_HTTP_BROKER_MODULE) || defined(CLIQ_MCP_STDIO_BROKER_MODULE)
static bool broker_no_echo(struct broker *broker, const unsigned char *bytes, size_t size) {
  return broker_no_echo_mode(broker, bytes, size, false);
}
#endif
#if defined(CLIQ_MCP_HTTP_BROKER_MODULE) || defined(CLIQ_MCP_STDIO_BROKER_MODULE)
static bool
mcp_no_echo_all(struct broker *broker, const unsigned char *bytes, size_t size)
{
    if (!broker_no_echo_mode(broker, bytes, size, true))
        return false;
    /*
     * A finite SSE tail may end halfway through UTF-8. Screen every valid scalar prefix independently too; an invalid
     * tail cannot suppress NFC and nested JSON-string screening of an earlier recoverable key.
     */
    size_t          at = 0;
    while (at < size) {
        const char     *end = NULL;
        bool            valid = g_utf8_validate((const char *)bytes + at, (gssize) (size - at), &end);
        size_t          count = valid ? size - at : (size_t) (end - ((const char *)bytes + at));
        if (count && !broker_no_echo_mode(broker, bytes + at, count, true))
            return false;
        at += count;
        if (!valid)
            at++;
    }
    return true;
}
#endif

#endif
