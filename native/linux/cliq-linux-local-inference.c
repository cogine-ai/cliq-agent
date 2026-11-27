#define _GNU_SOURCE
/* Fixed signed bootstrap, not an inference engine. The original namespace
 * owner verified/mounted the exact signed closure before this executable.
 * No caller argv, executable search, model write, pull or credential enters. */
#include "local-inference-protocol.h"
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>

static bool bootstrap_port(const char *text, uint32_t *port) {
  if (!text || !text[0] || strlen(text) > 5 || text[0] == '0') return false;
  uint32_t value = 0;
  for (const char *at = text; *at; ++at) { if (*at < '0' || *at > '9') return false; value = value * 10 + (uint32_t)(*at - '0'); }
  if (value < 49152 || value > 65535) return false;
  *port = value; return true;
}
static bool bootstrap_same(const struct cliq_local_service_packet *left, const struct cliq_local_service_packet *right) {
  return left->magic == CLIQ_LOCAL_SERVICE_MAGIC && left->version == 1 && !left->status &&
    memcmp(&left->binding, &right->binding, sizeof(left->binding)) == 0 &&
    memcmp(&left->resources, &right->resources, sizeof(left->resources)) == 0 &&
    memcmp(left->input_digest, right->input_digest, sizeof(left->input_digest)) == 0;
}
int main(int argc, char **argv) {
  uint32_t port;
  if (argc != 12 || strcmp(argv[1], "serve") || strcmp(argv[2], "--manifest") || strcmp(argv[3], "/models/model-manifest.json") ||
      strcmp(argv[4], "--model-root") || strcmp(argv[5], "/models/files") || strcmp(argv[6], "--tokenizer") ||
      strcmp(argv[7], "/models/tokenizer") || strcmp(argv[8], "--host") || strcmp(argv[9], "127.0.0.1") ||
      strcmp(argv[10], "--port") || !bootstrap_port(argv[11], &port) || getpid() != 2 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || !cliq_close_range(4, UINT_MAX)) return 64;
  struct cliq_local_service_packet origin; size_t count = 0; bool uncertain = false;
  if (!cliq_local_service_receive(3, &origin, NULL, 0, &count, 0, &uncertain) || count || uncertain ||
      origin.magic != CLIQ_LOCAL_SERVICE_MAGIC || origin.version != 1 || origin.status ||
      origin.command != CLIQ_LOCAL_SERVICE_CREATE_BLOCKED || origin.binding.port != port ||
      !cliq_local_service_binding_valid(&origin.binding) || !cliq_local_service_resources_valid(&origin.resources) ||
      !cliq_hex_digest(origin.input_digest)) return 70;
  struct cliq_local_service_packet reply = origin; reply.command = CLIQ_LOCAL_SERVICE_READY;
  reply.observation.bootstrap_pid = getpid();
  if (!cliq_process_token(getpid(), reply.observation.bootstrap_start) || !cliq_local_service_send(3, &reply, NULL, 0)) return 70;
  struct cliq_local_service_packet release;
  if (!cliq_local_service_receive(3, &release, NULL, 0, &count, 0, &uncertain) || count || uncertain ||
      !bootstrap_same(&release, &origin) || release.command != CLIQ_LOCAL_SERVICE_RELEASE_ENGINE) return 70;
  pid_t engine = fork();
  if (engine < 0) return 70;
  if (!engine) {
    if (close(3)) _exit(70);
    char host[64]; int length = snprintf(host, sizeof(host), "OLLAMA_HOST=127.0.0.1:%u", port);
    if (length <= 0 || (size_t)length >= sizeof(host)) _exit(70);
    char *const arguments[] = {"/runtime/bin/ollama", "serve", NULL};
    char *const environment[] = {"LANG=C", "LC_ALL=C", "HOME=/scratch/home", "TMPDIR=/scratch/tmp", host,
      "OLLAMA_MODELS=/models/files", "OLLAMA_NO_CLOUD=1", "OLLAMA_NOPRUNE=1", "OLLAMA_NOHISTORY=1", NULL};
    execve(arguments[0], arguments, environment); _exit(70);
  }
  reply.command = CLIQ_LOCAL_SERVICE_ACTIVATED;
  if (!cliq_local_service_send(3, &reply, NULL, 0)) return 70;
  /* Only the original namespace PID1 owns whole-domain stop. Losing this
   * private barrier channel ends this bootstrap and makes PID1 stop/reap all
   * actual Ollama, llama-server and discovery descendants. */
  for (;;) {
    int status; pid_t reaped = waitpid(engine, &status, WNOHANG);
    if (reaped == engine || (reaped < 0 && errno != EINTR)) return 70;
    struct pollfd control = {.fd = 3, .events = POLLIN}; int available = poll(&control, 1, 10);
    if (available < 0 && errno == EINTR) continue;
    if (available < 0 || available > 0) return 70;
  }
}
