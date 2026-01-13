// client.c
// mycord client implementation with configurable colors, proper timestamp printing,
// safe logout handling, packed struct parsing, and robust error reporting.

#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <stdint.h>

// Message types per spec
typedef enum MessageType {
    LOGIN = 0,
    LOGOUT = 1,
    MESSAGE_SEND = 2,
    MESSAGE_RECV = 10,
    DISCONNECT = 12,
    SYSTEM = 13
} message_type_t;

// Packed struct of exactly 1064 bytes
typedef struct __attribute__((packed)) Message {
    uint32_t type;
    uint32_t timestamp;
    char username[32];
    char message[1024];
} message_t;
_Static_assert(sizeof(message_t) == 1064, "message_t size must be 1064 bytes");

typedef struct Settings {
    struct sockaddr_in server;
    bool quiet;
    int socket_fd;
    volatile sig_atomic_t running;
    char username[32];
    bool ip_set;
    bool domain_set;
    char ip_str[INET_ADDRSTRLEN];
    int port;
} settings_t;

// Color definitions
static const char* COLOR_RED     = "\033[0;31m";
static const char* COLOR_GREEN   = "\033[0;32m";
static const char* COLOR_BLUE    = "\033[0;34m";
static const char* COLOR_YELLOW  = "\033[1;33m";
static const char* COLOR_MAGENTA = "\033[0;35m";
static const char* COLOR_CYAN    = "\033[0;36m";
static const char* COLOR_WHITE   = "\033[1;37m";
static const char* COLOR_GRAY    = "\033[90m";
static const char* COLOR_RESET   = "\033[0m";

static const char* mention_color = "\033[0;31m"; // default RED
static settings_t settings = {0};

// ---------- Utilities ----------

static void print_help(void) {
    printf("usage: ./client [-h] [--port PORT] [--ip IP] [--domain DOMAIN] [--quiet]\n\n");
    printf("mycord client\n\n");
    printf("options:\n");
    printf("  --help                show this help message and exit\n");
    printf("  --port PORT           port to connect to (default: 8080)\n");
    printf("  --ip IP               IP to connect to (default: \"127.0.0.1\")\n");
    printf("  --domain DOMAIN       Domain name to connect to (if domain is specified, IP must not be)\n");
    printf("  --quiet               do not perform alerts or mention highlighting\n");
    printf("  -c {RED,GREEN,BLUE,YELLOW,MAGENTA,CYAN,WHITE}, --color {RED,GREEN,BLUE,YELLOW,MAGENTA,CYAN,WHITE}\n");
    printf("                        color option (default: RED)\n\n");
    printf("examples:\n");
    printf("  ./client --help\n");
    printf("  ./client --port 1738\n");
    printf("  ./client --domain example.com\n");
}

static int valid_port(const char *s, int *out_port) {
    char *end = NULL;
    long p = strtol(s, &end, 10);
    if (!s || *s == '\0' || *end != '\0' || p < 1 || p > 65535) return 0;
    *out_port = (int)p;
    return 1;
}

static int ip_parse(const char *ip, struct in_addr *out) {
    return ip && inet_pton(AF_INET, ip, out) == 1;
}

static int resolve_domain_ipv4(const char *domain, char ip_out[INET_ADDRSTRLEN]) {
    struct hostent *he = gethostbyname(domain);
    if (!he || he->h_addrtype != AF_INET || !he->h_addr_list || !he->h_addr_list[0]) return 0;
    struct in_addr addr;
    memcpy(&addr, he->h_addr_list[0], sizeof(addr));
    return inet_ntop(AF_INET, &addr, ip_out, INET_ADDRSTRLEN) != NULL;
}

static ssize_t perform_full_read(void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(settings.socket_fd, (char*)buf + off, n - off);
        if (r > 0) { off += (size_t)r; continue; }
        if (r == 0) return 0;
        if (errno == EINTR) continue;
        return -1;
    }
    return (ssize_t)off;
}

static ssize_t perform_full_write(const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(settings.socket_fd, (const char*)buf + off, n - off);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    return (ssize_t)off;
}

// best-effort write (no error printing)
static void try_write_once(const void *buf, size_t n) {
    (void)write(settings.socket_fd, buf, n);
}

static void format_time(uint32_t ts, char *out, size_t out_sz) {
    time_t t = (time_t)ts;
    struct tm *tm = localtime(&t);
    if (!tm) { snprintf(out, out_sz, "0000-00-00 00:00:00"); return; }
    strftime(out, out_sz, "%Y-%m-%d %H:%M:%S", tm);
}

// ---------- Argument parsing / username ----------

int process_args(int argc, char *argv[]) {
    settings.quiet = false;
    settings.port = 8080;
    strncpy(settings.ip_str, "127.0.0.1", sizeof(settings.ip_str));
    settings.ip_set = false;
    settings.domain_set = false;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_help();
            exit(0);
        } else if (strcmp(arg, "--port") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --port requires a value\n"); return -1; }
            int p = 0;
            if (!valid_port(argv[++i], &p)) { fprintf(stderr, "Error: invalid port '%s'\n", argv[i]); return -1; }
            settings.port = p;
        } else if (strcmp(arg, "--ip") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --ip requires a value\n"); return -1; }
            const char *ip = argv[++i];
            struct in_addr tmp;
            if (!ip_parse(ip, &tmp)) { fprintf(stderr, "Error: invalid IP address '%s'\n", ip); return -1; }
            strncpy(settings.ip_str, ip, sizeof(settings.ip_str) - 1);
            settings.ip_set = true;
        } else if (strcmp(arg, "--domain") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --domain requires a value\n"); return -1; }
            const char *domain = argv[++i];
            char resolved[INET_ADDRSTRLEN] = {0};
            if (!resolve_domain_ipv4(domain, resolved)) { fprintf(stderr, "Error: DNS resolution failed for '%s'\n", domain); return -1; }
            strncpy(settings.ip_str, resolved, sizeof(settings.ip_str) - 1);
            settings.domain_set = true;
        } else if (strcmp(arg, "--quiet") == 0) {
            settings.quiet = true;
        } else if (strcmp(arg, "-c") == 0 || strcmp(arg, "--color") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --color requires a value\n"); return -1; }
            const char *val = argv[++i];
            if      (strcasecmp(val, "RED")     == 0) mention_color = COLOR_RED;
            else if (strcasecmp(val, "GREEN")   == 0) mention_color = COLOR_GREEN;
            else if (strcasecmp(val, "BLUE")    == 0) mention_color = COLOR_BLUE;
            else if (strcasecmp(val, "YELLOW")  == 0) mention_color = COLOR_YELLOW;
            else if (strcasecmp(val, "MAGENTA") == 0) mention_color = COLOR_MAGENTA;
            else if (strcasecmp(val, "CYAN")    == 0) mention_color = COLOR_CYAN;
            else if (strcasecmp(val, "WHITE")   == 0) mention_color = COLOR_WHITE;
            else { fprintf(stderr, "Error: invalid color '%s'\n", val); return -1; }
        } else {
            fprintf(stderr, "Error: unrecognized argument '%s'\n", arg);
            return -1;
        }
    }

    if (settings.ip_set && settings.domain_set) {
        fprintf(stderr, "Error: --ip must not be specified when --domain is provided\n");
        return -1;
    }

    memset(&settings.server, 0, sizeof(settings.server));
    settings.server.sin_family = AF_INET;
    settings.server.sin_port = htons(settings.port);
    if (inet_pton(AF_INET, settings.ip_str, &settings.server.sin_addr) != 1) {
        fprintf(stderr, "Error: invalid IP address '%s'\n", settings.ip_str);
        return -1;
    }

    return 0;
}

int get_username() {
    const char *env_user = getenv("USER");
    char buf[64] = {0};
    if (env_user && *env_user) {
        strncpy(buf, env_user, sizeof(buf) - 1);
    } else {
        FILE *fp = popen("whoami", "r");
        if (!fp) { fprintf(stderr, "Error: failed to get username via whoami\n"); return -1; }
        if (!fgets(buf, sizeof(buf), fp)) { fprintf(stderr, "Error: failed to read username from whoami\n"); pclose(fp); return -1; }
        pclose(fp);
        buf[strcspn(buf, "\n")] = '\0';
    }

    size_t n = strlen(buf);
    if (n == 0) { fprintf(stderr, "Error: empty username\n"); return -1; }
    if (n >= sizeof(settings.username)) { fprintf(stderr, "Error: username too long (max 31 characters)\n"); return -1; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (!isprint(c) || !isalnum(c)) {
            fprintf(stderr, "Error: invalid username '%s' (must be alphanumeric printable ASCII)\n", buf);
            return -1;
        }
    }

    strncpy(settings.username, buf, sizeof(settings.username) - 1);
    return 0;
}

// ---------- Signal handling ----------

void handle_signal(int sig) {
    (void)sig;
    if (!settings.running) return;
    settings.running = 0;

    if (settings.socket_fd >= 0) {
        message_t logout = (message_t){0};
        logout.type = htonl(LOGOUT);
        try_write_once(&logout, sizeof(logout)); // best-effort, no error printing
        close(settings.socket_fd);
        settings.socket_fd = -1;
    }
}

// ---------- Networking / threads ----------

static int send_login(void) {
    message_t m = (message_t){0};
    m.type = htonl(LOGIN);
    strncpy(m.username, settings.username, sizeof(m.username) - 1);
    if (perform_full_write(&m, sizeof(m)) < 0) {
        fprintf(stderr, "Error: write() failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int send_text(const char *text) {
    message_t m = (message_t){0};
    m.type = htonl(MESSAGE_SEND);
    strncpy(m.message, text, sizeof(m.message) - 1);
    if (perform_full_write(&m, sizeof(m)) < 0) {
        fprintf(stderr, "Error: write() failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static void print_disconnect(const char *reason) {
    fprintf(stderr, "%s[DISCONNECT] %s%s\n", COLOR_RED, reason, COLOR_RESET);
}

void* receive_messages_thread(void* arg) {
    (void)arg;
    message_t msg;
    while (settings.running) {
        ssize_t r = perform_full_read(&msg, sizeof(msg));
        if (!settings.running) break;  // shutting down; exit quietly
        if (r == 0) { fprintf(stderr, "Error: server closed connection\n"); settings.running = 0; break; }
        if (r < 0)  { fprintf(stderr, "Error: read() failed: %s\n", strerror(errno)); settings.running = 0; break; }

        uint32_t type = ntohl(msg.type);
        uint32_t ts   = ntohl(msg.timestamp);

        switch (type) {
            case MESSAGE_RECV: {
                char tsbuf[32];
                format_time(ts, tsbuf, sizeof(tsbuf));
                // Print timestamp and username once
                printf("[%s] %s: ", tsbuf, msg.username);
                // Message body with mention highlighting
                if (settings.quiet || settings.username[0] == '\0') {
                    printf("%s\n", msg.message);
                } else {
                    const char *uname = settings.username;
                    size_t ulen = strlen(uname);
                    const char *p = msg.message;
                    while (*p) {
                        const char *at = strchr(p, '@');
                        if (!at) { fputs(p, stdout); break; }
                        fwrite(p, 1, (size_t)(at - p), stdout);
                        if (strncmp(at + 1, uname, ulen) == 0) {
                            fputs("\a", stdout);
                            fputs(mention_color, stdout);
                            fwrite(at, 1, 1 + ulen, stdout);
                            fputs(COLOR_RESET, stdout);
                            p = at + 1 + ulen;
                        } else {
                            fputc('@', stdout);
                            p = at + 1;
                        }
                    }
                    fputc('\n', stdout);
                }
            } break;

            case SYSTEM:
                printf("%s[SYSTEM] %s%s\n", COLOR_GRAY, msg.message, COLOR_RESET);
                break;

            case DISCONNECT:
                print_disconnect(msg.message);
                settings.running = 0;
                break;

            default:
                fprintf(stderr, "Error: unknown message type %u\n", type);
                break;
        }
    }
    return NULL;
}

// ---------- Main ----------

int main(int argc, char *argv[]) {
    settings.socket_fd = -1;
    settings.running = 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0) { fprintf(stderr, "Error: sigaction(SIGINT) failed: %s\n", strerror(errno)); }
    if (sigaction(SIGTERM, &sa, NULL) < 0) { fprintf(stderr, "Error: sigaction(SIGTERM) failed: %s\n", strerror(errno)); }

    if (process_args(argc, argv) < 0) return 1;
    if (get_username() < 0) return 1;

    settings.socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (settings.socket_fd < 0) { fprintf(stderr, "Error: socket() failed: %s\n", strerror(errno)); return 1; }

    if (connect(settings.socket_fd, (struct sockaddr*)&settings.server, sizeof(settings.server)) < 0) {
        fprintf(stderr, "Error: connect() failed: %s\n", strerror(errno));
        close(settings.socket_fd);
        settings.socket_fd = -1;
        return 1;
    }

    if (send_login() < 0) {
        close(settings.socket_fd);
        settings.socket_fd = -1;
        return 1;
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, receive_messages_thread, NULL) != 0) {
        fprintf(stderr, "Error: pthread_create failed\n");
        close(settings.socket_fd);
        settings.socket_fd = -1;
        return 1;
    }

    // Main thread: read STDIN lines
    char *line = NULL;
    size_t cap = 0;
    while (settings.running) {
        errno = 0;
        ssize_t gl = getline(&line, &cap, stdin);
        if (gl == -1) {
            if (feof(stdin)) {
                message_t logout = (message_t){0};
                logout.type = htonl(LOGOUT);
                try_write_once(&logout, sizeof(logout)); // best-effort
                break;
            } else if (errno == EINTR) {
                if (!settings.running) break;
                continue;
            } else {
                fprintf(stderr, "Error: getline() failed: %s\n", strerror(errno));
                break;
            }
        }

        if (gl > 0 && line[gl - 1] == '\n') line[gl - 1] = '\0';
        size_t L = strlen(line);

        // Validate message
        if (L < 1 || L > 1023) { fprintf(stderr, "Error: invalid message length (must be 1-1023)\n"); continue; }
        bool bad = false;
        for (size_t i = 0; i < L; i++) {
            unsigned char c = (unsigned char)line[i];
            if (!isprint(c)) { bad = true; break; }
        }
        if (bad) { fprintf(stderr, "Error: non-printable character in message\n"); continue; }

        if (send_text(line) < 0) break;
    }

    settings.running = 0;
    pthread_join(tid, NULL);
    if (settings.socket_fd >= 0) { close(settings.socket_fd); settings.socket_fd = -1; }
    free(line);
    return 0;
}
