/**
 * bg3se-console.c - Interactive console client for BG3SE
 *
 * Connects to the BG3SE Unix domain socket for real-time Lua execution.
 *
 * Features:
 * - Readline-based command line editing with history
 * - ANSI color output support
 * - Multi-line input with --[[ and ]]-- delimiters
 * - Automatic reconnection on disconnect
 *
 * Build:
 *   cc -o bg3se-console bg3se-console.c -lreadline
 *
 * Usage:
 *   ./bg3se-console
 *   ./bg3se-console -s /path/to/socket
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <fcntl.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>

// Default socket path (same as CONSOLE_SOCKET_PATH in console.h)
#define DEFAULT_SOCKET_PATH "/tmp/bg3se.sock"

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

// Global state
static int g_socket_fd = -1;
static const char *g_socket_path = DEFAULT_SOCKET_PATH;
static volatile int g_running = 1;
static int g_in_multiline = 0;
static char *g_multiline_buffer = NULL;
static size_t g_multiline_size = 0;
static size_t g_multiline_capacity = 0;

// Forward declarations
static int connect_to_server(void);
static void disconnect_from_server(void);
static void send_line(const char *line);
static void process_server_output(void);
static void cleanup(void);
static void signal_handler(int sig);
static void append_to_multiline(const char *line);

/**
 * Connect to the BG3SE socket server.
 */
static int connect_to_server(void) {
    if (g_socket_fd >= 0) {
        return 1;  // Already connected
    }

    g_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_socket_fd < 0) {
        fprintf(stderr, "%sError: Failed to create socket: %s%s\n",
                COLOR_RED, strerror(errno), COLOR_RESET);
        return 0;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_socket_path, sizeof(addr.sun_path) - 1);

    if (connect(g_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(g_socket_fd);
        g_socket_fd = -1;
        return 0;
    }

    // Set non-blocking for reading
    int flags = fcntl(g_socket_fd, F_GETFL, 0);
    fcntl(g_socket_fd, F_SETFL, flags | O_NONBLOCK);

    return 1;
}

/**
 * Disconnect from the server.
 */
static void disconnect_from_server(void) {
    if (g_socket_fd >= 0) {
        close(g_socket_fd);
        g_socket_fd = -1;
    }
}

/**
 * Send a line to the server.
 */
static void send_line(const char *line) {
    if (g_socket_fd < 0) {
        fprintf(stderr, "%sNot connected%s\n", COLOR_RED, COLOR_RESET);
        return;
    }

    size_t len = strlen(line);
    char *buf = malloc(len + 2);  // +2 for \n and null
    if (!buf) return;

    memcpy(buf, line, len);
    buf[len] = '\n';
    buf[len + 1] = '\0';

    ssize_t written = write(g_socket_fd, buf, len + 1);
    free(buf);

    if (written < 0) {
        fprintf(stderr, "%sConnection lost%s\n", COLOR_RED, COLOR_RESET);
        disconnect_from_server();
    }
}

/**
 * Append a line to the multi-line buffer.
 */
static void append_to_multiline(const char *line) {
    size_t line_len = strlen(line);
    size_t needed = g_multiline_size + line_len + 2;  // +1 for \n, +1 for null

    if (needed > g_multiline_capacity) {
        size_t new_cap = (needed > g_multiline_capacity * 2) ? needed : g_multiline_capacity * 2;
        if (new_cap < 1024) new_cap = 1024;
        char *new_buf = realloc(g_multiline_buffer, new_cap);
        if (!new_buf) {
            fprintf(stderr, "%sOut of memory%s\n", COLOR_RED, COLOR_RESET);
            return;
        }
        g_multiline_buffer = new_buf;
        g_multiline_capacity = new_cap;
    }

    memcpy(g_multiline_buffer + g_multiline_size, line, line_len);
    g_multiline_size += line_len;
    g_multiline_buffer[g_multiline_size++] = '\n';
    g_multiline_buffer[g_multiline_size] = '\0';
}

/**
 * Process output from the server (non-blocking).
 */
static void process_server_output(void) {
    if (g_socket_fd < 0) return;

    char buf[4096];
    while (1) {
        ssize_t n = read(g_socket_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            // Print server output directly (may contain ANSI colors)
            printf("%s", buf);
            fflush(stdout);
        } else if (n == 0) {
            // Server closed connection
            printf("%s[Disconnected from server]%s\n", COLOR_YELLOW, COLOR_RESET);
            disconnect_from_server();
            break;
        } else {
            // EAGAIN/EWOULDBLOCK means no more data
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            // Real error
            printf("%s[Connection error: %s]%s\n", COLOR_RED, strerror(errno), COLOR_RESET);
            disconnect_from_server();
            break;
        }
    }
}

/**
 * Cleanup on exit.
 */
static void cleanup(void) {
    disconnect_from_server();
    free(g_multiline_buffer);
    g_multiline_buffer = NULL;
}

/**
 * Signal handler for graceful shutdown.
 */
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n");
}

/**
 * Print usage and exit.
 */
static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -s PATH   Socket path (default: %s)\n", DEFAULT_SOCKET_PATH);
    printf("  -h        Show this help\n");
    printf("\n");
    printf("Interactive Commands:\n");
    printf("  !help     Show available console commands\n");
    printf("  !status   Show connection/event status\n");
    printf("  !events   List registered event handlers\n");
    printf("  !quit     Disconnect and exit\n");
    printf("\n");
    printf("Multi-line Input:\n");
    printf("  Start with --[[ and end with ]]-- for multi-line Lua blocks\n");
    printf("\n");
}

/**
 * Get the appropriate prompt.
 */
static const char *get_prompt(void) {
    if (g_in_multiline) {
        return "... ";
    }
    if (g_socket_fd >= 0) {
        return COLOR_GREEN "bg3se> " COLOR_RESET;
    }
    return COLOR_RED "(disconnected)> " COLOR_RESET;
}

/**
 * Main entry point.
 */
int main(int argc, char **argv) {
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            g_socket_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);  // Ignore broken pipe

    // Register cleanup
    atexit(cleanup);

    // Print banner
    printf("%s%s╔══════════════════════════════════════╗%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s%s║   BG3SE Console Client v0.1          ║%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s%s╚══════════════════════════════════════╝%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("\n");

    // Try initial connection
    if (connect_to_server()) {
        printf("%sConnected to %s%s\n\n", COLOR_GREEN, g_socket_path, COLOR_RESET);
    } else {
        printf("%sNo server at %s - will retry on input%s\n\n",
               COLOR_YELLOW, g_socket_path, COLOR_RESET);
    }

    // Initialize readline
    using_history();

    // Load history from file
    char *home = getenv("HOME");
    char history_path[512] = {0};
    if (home) {
        snprintf(history_path, sizeof(history_path), "%s/.bg3se_history", home);
        read_history(history_path);
    }

    // Main loop
    while (g_running) {
        // Check for server output first
        process_server_output();

        // Read user input (with timeout to check server output periodically)
        fd_set read_fds;
        struct timeval tv;

        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        if (g_socket_fd >= 0) {
            FD_SET(g_socket_fd, &read_fds);
        }

        tv.tv_sec = 0;
        tv.tv_usec = 100000;  // 100ms

        int max_fd = (g_socket_fd > STDIN_FILENO) ? g_socket_fd : STDIN_FILENO;
        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Check for server output
        if (g_socket_fd >= 0 && FD_ISSET(g_socket_fd, &read_fds)) {
            process_server_output();
        }

        // Check for user input
        if (ready > 0 && FD_ISSET(STDIN_FILENO, &read_fds)) {
            char *line = readline(get_prompt());
            if (!line) {
                // EOF (Ctrl+D)
                printf("\n");
                break;
            }

            // Skip empty lines
            if (line[0] == '\0') {
                free(line);
                continue;
            }

            // Add to history
            add_history(line);

            // Handle !quit locally
            if (strcmp(line, "!quit") == 0 || strcmp(line, "!exit") == 0) {
                free(line);
                break;
            }

            // Handle !connect for manual reconnection
            if (strcmp(line, "!connect") == 0) {
                if (g_socket_fd >= 0) {
                    printf("%sAlready connected%s\n", COLOR_YELLOW, COLOR_RESET);
                } else if (connect_to_server()) {
                    printf("%sConnected to %s%s\n", COLOR_GREEN, g_socket_path, COLOR_RESET);
                } else {
                    printf("%sFailed to connect: %s%s\n", COLOR_RED, strerror(errno), COLOR_RESET);
                }
                free(line);
                continue;
            }

            // Check for multi-line start
            if (strstr(line, "--[[") != NULL) {
                g_in_multiline = 1;
                append_to_multiline(line);
                free(line);
                continue;
            }

            // Check for multi-line end
            if (g_in_multiline) {
                append_to_multiline(line);
                if (strstr(line, "]]--") != NULL) {
                    // End of multi-line, send the whole buffer
                    g_in_multiline = 0;

                    // Try to connect if not connected
                    if (g_socket_fd < 0) {
                        if (!connect_to_server()) {
                            printf("%sFailed to connect: %s%s\n",
                                   COLOR_RED, strerror(errno), COLOR_RESET);
                            // Clear multiline buffer
                            g_multiline_size = 0;
                            free(line);
                            continue;
                        }
                        printf("%sConnected to %s%s\n", COLOR_GREEN, g_socket_path, COLOR_RESET);
                    }

                    // Send line by line
                    char *start = g_multiline_buffer;
                    char *end;
                    while ((end = strchr(start, '\n')) != NULL) {
                        *end = '\0';
                        send_line(start);
                        *end = '\n';
                        start = end + 1;
                    }

                    // Clear multiline buffer
                    g_multiline_size = 0;
                }
                free(line);
                continue;
            }

            // Try to connect if not connected
            if (g_socket_fd < 0) {
                if (!connect_to_server()) {
                    printf("%sFailed to connect: %s%s\n", COLOR_RED, strerror(errno), COLOR_RESET);
                    free(line);
                    continue;
                }
                printf("%sConnected to %s%s\n", COLOR_GREEN, g_socket_path, COLOR_RESET);
            }

            // Send single line
            send_line(line);
            free(line);

            // Give server time to respond
            usleep(50000);  // 50ms
            process_server_output();
        }
    }

    // Save history
    if (history_path[0]) {
        write_history(history_path);
    }

    printf("%sGoodbye!%s\n", COLOR_CYAN, COLOR_RESET);
    return 0;
}
