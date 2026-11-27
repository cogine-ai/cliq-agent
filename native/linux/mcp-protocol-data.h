#ifndef CLIQ_MCP_PROTOCOL_DATA_H
#define CLIQ_MCP_PROTOCOL_DATA_H
/* Original bounded MCP JSON/frame decoder; retained data only, no owner or I/O. */
#define MCP_MAX_NODES 20002u
#define MCP_MAX_ENTRIES 10000u
#define MCP_PROTOCOL_BODY_CAP UINT32_C(1048576)
static int mcp_protocol_hex_digit(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}
struct mcp_json_node {
    size_t          start, end;
    unsigned        child, next;
    char            type;
};
struct mcp_json {
    const unsigned char *bytes;
    size_t          size, at;
    struct mcp_json_node *nodes;
    unsigned        count, entries;
    /* Copies used by semantic readers report allocation failure to the same
     * original parse. A bounded malformed payload is not an allocation proof. */
    bool            allocation_failed;
    bool           *allocation_failure;
};
static void
mcp_json_allocation_failed(const struct mcp_json *json)
{
    if (json->allocation_failure)
        *json->allocation_failure = true;
}
struct mcp_frame {
    unsigned char  *body;
    size_t          size;
    char            digest[65];
    unsigned char  *id;
    size_t          id_size;
};
/*
 * The live parser is deliberately protocol-only. Full initialize/tool/result schemas are independently recomputed by
 * Supervisor from actual captures.
 */
static void
mcp_json_space(struct mcp_json *json)
{
    while (json->at < json->size && strchr(" \t\r\n", json->bytes[json->at]))
        json->at++;
}
static bool
mcp_json_string(struct mcp_json *json, GString * decoded)
{
    if (json->at == json->size || json->bytes[json->at++] != '"')
        return false;
    while (json->at < json->size) {
        unsigned char   byte = json->bytes[json->at++];
        if (byte == '"')
            return true;
        if (byte < 0x20)
            return false;
        if (byte == '\\') {
            if (json->at == json->size)
                return false;
            byte = json->bytes[json->at++];
            if (byte == 'u') {
                unsigned        point = 0;
                if (json->size - json->at < 4)
                    return false;
                for (unsigned i = 0; i < 4; i++) {
                    int             digit = mcp_protocol_hex_digit(json->bytes[json->at++]);
                    if (digit < 0)
                        return false;
                    point = point * 16 + (unsigned)digit;
                }
                if (point >= 0xd800 && point <= 0xdbff) {
                    if (json->size - json->at < 6 || json->bytes[json->at++] != '\\' || json->bytes[json->at++] != 'u')
                        return false;
                    unsigned        low = 0;
                    for (unsigned i = 0; i < 4; i++) {
                        int             digit = mcp_protocol_hex_digit(json->bytes[json->at++]);
                        if (digit < 0)
                            return false;
                        low = low * 16 + (unsigned)digit;
                    }
                    if (low < 0xdc00 || low > 0xdfff)
                        return false;
                    point = 0x10000 + (point - 0xd800) * 1024 + low - 0xdc00;
                } else if (point >= 0xdc00 && point <= 0xdfff)
                    return false;
                char            encoded[6];
                int             size = g_unichar_to_utf8(point, encoded);
                if (decoded)
                    g_string_append_len(decoded, encoded, size);
                continue;
            }
            if (byte == 'b')
                byte = '\b';
            else if (byte == 'f')
                byte = '\f';
            else if (byte == 'n')
                byte = '\n';
            else if (byte == 'r')
                byte = '\r';
            else if (byte == 't')
                byte = '\t';
            else if (byte != '"' && byte != '\\' && byte != '/')
                return false;
        }
        if (decoded)
            g_string_append_c(decoded, (char)byte);
    }
    return false;
}
static bool
mcp_json_value(struct mcp_json *json, unsigned depth, unsigned *result)
{
    mcp_json_space(json);
    if (json->at == json->size || json->count + 1 >= MCP_MAX_NODES)
        return false;
    unsigned char   byte = json->bytes[json->at];
    if ((byte == '{' || byte == '[') && depth >= 32)
        return false;
    unsigned        index = ++json->count;
    struct mcp_json_node *node = &json->nodes[index];
    *result = index;
    node->start = json->at;
    node->type = (char)byte;
    if (byte == '"') {
        if (!mcp_json_string(json, NULL))
            return false;
    } else if (byte == '{' || byte == '[') {
        json->at++;
        mcp_json_space(json);
        unsigned        last = 0;
        GHashTable     *keys = byte == '{' ? g_hash_table_new_full(g_bytes_hash, g_bytes_equal, (GDestroyNotify) g_bytes_unref, NULL) : NULL;
        bool            valid = true;
        if (byte == '{' && !keys) {
            mcp_json_allocation_failed(json);
            return false;
        }
        if (json->at < json->size && json->bytes[json->at] == (byte == '{' ? '}' : ']'))
            json->at++;
        else
            for (;;) {
                if (++json->entries > MCP_MAX_ENTRIES) {
                    valid = false;
                    break;
                }
                if (byte == '{') {
                    unsigned        key = ++json->count;
                    if (key + 1 >= MCP_MAX_NODES) {
                        valid = false;
                        break;
                    }
                    struct mcp_json_node *key_node = &json->nodes[key];
                    key_node->start = json->at;
                    key_node->type = '"';
                    GString        *decoded = g_string_new(NULL);
                    if (!decoded)
                        mcp_json_allocation_failed(json);
                    valid = decoded && mcp_json_string(json, decoded);
                    if (valid) {
                        GBytes         *name = g_bytes_new(decoded->str, decoded->len);
                        if (!name) {
                            mcp_json_allocation_failed(json);
                            valid = false;
                        } else if (g_hash_table_contains(keys, name)) {
                            g_bytes_unref(name);
                            valid = false;
                        } else
                            g_hash_table_add(keys, name);
                    }
                    if (decoded)
                        g_string_free(decoded, TRUE);
                    key_node->end = json->at;
                    mcp_json_space(json);
                    if (!valid || json->at == json->size || json->bytes[json->at++] != ':') {
                        valid = false;
                        break;
                    }
                    if (last)
                        json->nodes[last].next = key;
                    else
                        node->child = key;
                    last = key;
                }
                unsigned        child;
                if (!mcp_json_value(json, depth + 1, &child)) {
                    valid = false;
                    break;
                }
                if (last)
                    json->nodes[last].next = child;
                else
                    node->child = child;
                last = child;
                mcp_json_space(json);
                if (json->at == json->size) {
                    valid = false;
                    break;
                }
                unsigned char   end = json->bytes[json->at++];
                if (end == (byte == '{' ? '}' : ']'))
                    break;
                if (end != ',') {
                    valid = false;
                    break;
                }
                mcp_json_space(json);
            }
        if (keys)
            g_hash_table_unref(keys);
        if (!valid)
            return false;
    } else if (byte == 't' || byte == 'f' || byte == 'n') {
        const char     *literal = byte == 't' ? "true" : byte == 'f' ? "false" : "null";
        size_t          size = strlen(literal);
        if (json->size - json->at < size || memcmp(json->bytes + json->at, literal, size))
            return false;
        json->at += size;
    } else {
        node->type = '#';
        if (byte == '-') {
            json->at++;
            if (json->at == json->size)
                return false;
        }
        if (json->bytes[json->at] == '0')
            json->at++;
        else {
            if (json->bytes[json->at] < '1' || json->bytes[json->at] > '9')
                return false;
            while (json->at < json->size && json->bytes[json->at] >= '0' && json->bytes[json->at] <= '9')
                json->at++;
        }
        if (json->at < json->size && json->bytes[json->at] == '.') {
            json->at++;
            size_t          start = json->at;
            while (json->at < json->size && json->bytes[json->at] >= '0' && json->bytes[json->at] <= '9')
                json->at++;
            if (start == json->at)
                return false;
        }
        if (json->at < json->size && (json->bytes[json->at] == 'e' || json->bytes[json->at] == 'E')) {
            json->at++;
            if (json->at < json->size && (json->bytes[json->at] == '+' || json->bytes[json->at] == '-'))
                json->at++;
            size_t          start = json->at;
            while (json->at < json->size && json->bytes[json->at] >= '0' && json->bytes[json->at] <= '9')
                json->at++;
            if (start == json->at)
                return false;
        }
        char           *number = g_strndup((const char *)json->bytes + node->start, json->at - node->start), *end = NULL;
        if (!number)
            mcp_json_allocation_failed(json);
        double          value = number ? g_ascii_strtod(number, &end) : INFINITY;
        bool            valid = number && end && !*end && isfinite(value);
        g_free(number);
        if (!valid)
            return false;
    }
    node->end = json->at;
    return true;
}
static bool
mcp_json_parse(const unsigned char *bytes, size_t size, struct mcp_json *json)
{
    memset(json, 0, sizeof(*json));
    json->allocation_failure = &json->allocation_failed;
    if (!size || size > MCP_PROTOCOL_BODY_CAP || !g_utf8_validate((const char *)bytes, (gssize) size, NULL))
        return false;
    json->bytes = bytes;
    json->size = size;
    json->nodes = calloc(MCP_MAX_NODES, sizeof(*json->nodes));
    if (!json->nodes)
        mcp_json_allocation_failed(json);
    unsigned        root;
    bool            valid = json->nodes && mcp_json_value(json, 0, &root);
    mcp_json_space(json);
    if (!valid || json->at != size || root != 1) {
        free(json->nodes);
        json->nodes = NULL;
        return false;
    }
    return true;
}
static bool
mcp_json_text(const struct mcp_json *json, unsigned index, const char *expected)
{
    if (!index || json->nodes[index].type != '"')
        return false;
    struct mcp_json copy = *json;
    copy.at = json->nodes[index].start;
    GString        *decoded = g_string_new(NULL);
    if (!decoded)
        mcp_json_allocation_failed(json);
    bool            valid = decoded && mcp_json_string(&copy, decoded) && decoded->len == strlen(expected) && !memcmp(decoded->str, expected, decoded->len);
    if (decoded)
        g_string_free(decoded, TRUE);
    return valid;
}
static unsigned
mcp_json_member(const struct mcp_json *json, unsigned object, const char *name)
{
    if (!object || json->nodes[object].type != '{')
        return 0;
    for (unsigned key = json->nodes[object].child; key;) {
        unsigned        value = json->nodes[key].next;
        if (mcp_json_text(json, key, name))
            return value;
        key = json->nodes[value].next;
    }
    return 0;
}
static bool
mcp_json_keys(const struct mcp_json *json, unsigned object, const char *const *allowed, size_t count)
{
    if (!object || json->nodes[object].type != '{')
        return false;
    for (unsigned key = json->nodes[object].child; key;) {
        bool            known = false;
        for (size_t i = 0; i < count; i++)
            known |= mcp_json_text(json, key, allowed[i]);
        if (!known)
            return false;
        unsigned        value = json->nodes[key].next;
        key = json->nodes[value].next;
    }
    return true;
}
static bool
mcp_json_id(const struct mcp_json *json, unsigned index, unsigned char **output, size_t * size)
{
    if (!index)
        return false;
    const struct mcp_json_node *node = &json->nodes[index];
    if (node->type == '"') {
        struct mcp_json copy = *json;
        copy.at = node->start;
        GString        *decoded = g_string_new(NULL);
        if (!decoded)
            mcp_json_allocation_failed(json);
        bool            valid = decoded && mcp_json_string(&copy, decoded);
        if (valid) {
            *size = decoded->len + 1;
            *output = malloc(*size);
            valid = *output != NULL;
            if (!valid)
                mcp_json_allocation_failed(json);
            if (valid) {
                (*output)[0] = 's';
                memcpy(*output + 1, decoded->str, decoded->len);
            }
        }
        if (decoded)
            g_string_free(decoded, TRUE);
        return valid;
    }
    if (node->type != '#')
        return false;
    char           *number = g_strndup((const char *)json->bytes + node->start, node->end - node->start), *end = NULL;
    if (!number)
        mcp_json_allocation_failed(json);
    double          value = number ? g_ascii_strtod(number, &end) : INFINITY;
    bool            valid = number && end && !*end && isfinite(value) && fabs(value) <= 9007199254740991.0 && trunc(value) == value;
    if (valid) {
        char            encoded[64];
        int             count = snprintf(encoded, sizeof(encoded), "n%.0f", value == 0 ? 0 : value);
        *size = (size_t) count;
        *output = malloc(*size);
        valid = count > 0 && *output;
        if (!*output)
            mcp_json_allocation_failed(json);
        if (valid)
            memcpy(*output, encoded, *size);
    }
    g_free(number);
    return valid;
}
static const char *
mcp_phase_name(unsigned phase)
{
    static const char *names[] = {"initialize", "initialized", "tools_list", "tools_call"};
    return phase < 4 ? names[phase] : "invalid";
}
static bool
mcp_frame_valid(struct mcp_frame *frame, unsigned phase)
{
    struct mcp_json json;
    if (!mcp_json_parse(frame->body, frame->size, &json))
        return false;
    const char     *keys[] = {"jsonrpc", "id", "method", "params"};
    static const char *methods[] = {"initialize", "notifications/initialized", "tools/list", "tools/call"};
    unsigned        id = mcp_json_member(&json, 1, "id"), params = mcp_json_member(&json, 1, "params");
    bool            valid = mcp_json_keys(&json, 1, keys, 4) && mcp_json_text(&json, mcp_json_member(&json, 1, "jsonrpc"), "2.0") &&
    mcp_json_text(&json, mcp_json_member(&json, 1, "method"), methods[phase]);
    if (phase == 1)
        valid = valid && !id && !params;
    else
        valid = valid && mcp_json_id(&json, id, &frame->id, &frame->id_size);
    if (phase == 0) {
        const char     *param_keys[] = {"protocolVersion", "capabilities", "clientInfo"};
        unsigned        caps = mcp_json_member(&json, params, "capabilities"), info = mcp_json_member(&json, params, "clientInfo");
        const char     *info_keys[] = {"name", "version"};
        valid = valid && mcp_json_keys(&json, params, param_keys, 3) && mcp_json_text(&json, mcp_json_member(&json, params, "protocolVersion"), "2025-11-25") &&
            caps && json.nodes[caps].type == '{' && !json.nodes[caps].child && mcp_json_keys(&json, info, info_keys, 2) &&
            mcp_json_text(&json, mcp_json_member(&json, info, "name"), "@cogineai/cliq") && mcp_json_member(&json, info, "version") && json.nodes[mcp_json_member(&json, info, "version")].type == '"';
    } else if (phase == 2)
        valid = valid && !params;
    else if (phase == 3) {
        const char     *param_keys[] = {"name", "arguments"};
        unsigned        name = mcp_json_member(&json, params, "name"), arguments = mcp_json_member(&json, params, "arguments");
        valid = valid && mcp_json_keys(&json, params, param_keys, 2) && name && json.nodes[name].type == '"' && arguments && json.nodes[arguments].type == '{';
    }
    free(json.nodes);
    return valid;
}

#endif
