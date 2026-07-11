#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <bpf/bpf.h>
#include <termios.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include "trace.h"

void trace_apply_filters(unsigned int *filters, int count);

#define MAX_SEEN_INDICES 4096
static unsigned int seen_indices[MAX_SEEN_INDICES];
static int seen_count = 0;

#define MAX_BUFFERED_EVENTS 2000000
static struct event buffered_events[MAX_BUFFERED_EVENTS];
static int buffered_count = 0;
static unsigned long long userspace_drops = 0;
static int dedupe_mode = 0;
static int verbose = 0;

static struct event unique_events[MAX_SEEN_INDICES];
static int unique_count = 0;

/* Scroll state for dedupe TUI */
static int scroll_offset = 0;
static int scroll_follow = 1; /* auto-follow newest when at top */

/* Terminal state for raw mode restore */
static struct termios orig_termios;
static int raw_mode_active = 0;
static volatile sig_atomic_t got_signal = 0;
static int terminal_restored = 0;
static unsigned long long last_render_ts_global = 0;

static int get_terminal_rows(void);
static int get_terminal_cols(void);

static void restore_terminal(void)
{
    if (terminal_restored) return;
    terminal_restored = 1;

    if (raw_mode_active) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        raw_mode_active = 0;
    }

    if (dedupe_mode && isatty(STDOUT_FILENO)) {
        /* Leave alternate screen buffer */
        printf("\033[?1049l");
        printf("\033[?25h"); /* show cursor */
        fflush(stdout);

        /* Dump final viewport to the normal screen so it persists */
        if (unique_count > 0 && last_render_ts_global > 0) {
            int visible_rows = get_terminal_rows() - 1;
            int end = scroll_offset + visible_rows;
            if (end > unique_count) end = unique_count;
            for (int i = scroll_offset; i < end; i++) {
                trace_print(&unique_events[i], '*', last_render_ts_global, 1);
            }
            fflush(stdout);
        }
    }
}

static void signal_handler(int sig)
{
    (void)sig;
    got_signal = 1;
}

static void enter_raw_mode(void)
{
    if (!isatty(STDIN_FILENO)) return;
    tcgetattr(STDIN_FILENO, &orig_termios);
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON | ISIG);
    raw.c_iflag &= ~(IXON | ICRNL);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    raw_mode_active = 1;
}

static void enter_alt_screen(void)
{
    if (!isatty(STDOUT_FILENO)) return;
    printf("\033[?1049h"); /* enter alternate screen */
    printf("\033[?25l");   /* hide cursor */
    printf("\033[2J");     /* clear screen */
    fflush(stdout);
}

static int get_terminal_rows(void)
{
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1 && w.ws_row > 0)
        return w.ws_row;
    return 24;
}

static int get_terminal_cols(void)
{
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1 && w.ws_col > 0)
        return w.ws_col;
    return 80;
}

/* Process keyboard input, returns 1 if quit requested */
static int handle_keyboard(void)
{
    unsigned char buf[32];
    int n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) return 0;

    int visible_rows = get_terminal_rows() - 1; /* 1 for status bar */
    int max_offset = unique_count > visible_rows ? unique_count - visible_rows : 0;

    for (int i = 0; i < n; i++) {
        if (buf[i] == 'q' || buf[i] == 'Q' || buf[i] == 3 /* Ctrl-C */) {
            return 1;
        }

        /* ESC sequence */
        if (buf[i] == 0x1b && i + 2 < n && buf[i + 1] == '[') {
            char code = buf[i + 2];
            if (code == 'A') { /* Up arrow */
                scroll_follow = 0;
                if (scroll_offset > 0) scroll_offset--;
            } else if (code == 'B') { /* Down arrow */
                scroll_follow = 0;
                if (scroll_offset < max_offset) scroll_offset++;
            } else if (code == '5') { /* Page Up - \033[5~ */
                scroll_follow = 0;
                scroll_offset -= visible_rows;
                if (scroll_offset < 0) scroll_offset = 0;
                if (i + 3 < n && buf[i + 3] == '~') i++;
            } else if (code == '6') { /* Page Down - \033[6~ */
                scroll_follow = 0;
                scroll_offset += visible_rows;
                if (scroll_offset > max_offset) scroll_offset = max_offset;
                if (i + 3 < n && buf[i + 3] == '~') i++;
            } else if (code == 'H') { /* Home */
                scroll_follow = 1;
                scroll_offset = 0;
            } else if (code == 'F') { /* End */
                scroll_follow = 0;
                scroll_offset = max_offset;
            }
            i += 2; /* skip ESC [ code */
        }
    }

    /* Clamp */
    if (scroll_offset < 0) scroll_offset = 0;
    if (scroll_offset > max_offset) scroll_offset = max_offset;

    return 0;
}

static int cmp_event_ts_desc(const void *a, const void *b) {
    const struct event *ea = a;
    const struct event *eb = b;
    if (ea->ts > eb->ts) return -1;
    if (ea->ts < eb->ts) return 1;
    return 0;
}

static int is_seen(unsigned int index) {
    for (int i = 0; i < seen_count; i++) {
        if (seen_indices[i] == index) return 1;
    }
    return 0;
}

static void mark_seen(unsigned int index) {
    if (seen_count < MAX_SEEN_INDICES) {
        seen_indices[seen_count++] = index;
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (buffered_count < MAX_BUFFERED_EVENTS) {
        buffered_events[buffered_count++] = *e;
    } else {
        userspace_drops++;
    }
    return 0;
}

static void dedupe_render(unsigned long long current_time_ns)
{
    last_render_ts_global = current_time_ns;
    int is_tty = isatty(STDOUT_FILENO);
    int visible_rows = is_tty ? get_terminal_rows() - 1 : unique_count; /* 1 for status */
    int cols = is_tty ? get_terminal_cols() : 160;
    int max_offset = unique_count > visible_rows ? unique_count - visible_rows : 0;

    /* Auto-follow: keep scroll at top (newest) */
    if (scroll_follow) {
        scroll_offset = 0;
    }

    /* Clamp scroll */
    if (scroll_offset > max_offset) scroll_offset = max_offset;
    if (scroll_offset < 0) scroll_offset = 0;

    if (is_tty) {
        printf("\033[H"); /* cursor home */
    }

    int end = scroll_offset + visible_rows;
    if (end > unique_count) end = unique_count;

    for (int i = scroll_offset; i < end; i++) {
        trace_print(&unique_events[i], '*', current_time_ns, 1);
    }

    /* Clear remaining lines if list is shorter than screen */
    if (is_tty) {
        for (int i = end - scroll_offset; i < visible_rows; i++) {
            printf("\033[K\n");
        }
    }

    /* Status bar */
    if (is_tty) {
        char status[256];
        int from = unique_count > 0 ? scroll_offset + 1 : 0;
        int to = end;
        snprintf(status, sizeof(status),
                 " [%d-%d of %d unique] %s | q:quit  \xe2\x86\x91\xe2\x86\x93:scroll  PgUp/PgDn:page  Home:top  End:bottom",
                 from, to, unique_count,
                 scroll_follow ? "FOLLOW" : "SCROLL");
        /* Reverse video for status bar */
        printf("\033[7m%-*.*s\033[0m", cols, cols, status);
        fflush(stdout);
    }
}

static void flush_events(unsigned long long current_time_ns)
{
    if (dedupe_mode) {
        for (int i = 0; i < buffered_count; i++) {
            struct event *new_e = &buffered_events[i];
            int found = 0;
            for (int j = 0; j < unique_count; j++) {
                if (unique_events[j].index == new_e->index) {
                    unique_events[j] = *new_e;
                    found = 1;
                    break;
                }
            }
            if (!found && unique_count < MAX_SEEN_INDICES) {
                unique_events[unique_count++] = *new_e;
            }
        }

        qsort(unique_events, unique_count, sizeof(struct event), cmp_event_ts_desc);
        dedupe_render(current_time_ns);
    } else {
        for (int i = 0; i < buffered_count; i++) {
            struct event *e = &buffered_events[i];
            char prefix = '*';

            if (is_seen(e->index)) {
                prefix = ' ';
            } else {
                mark_seen(e->index);
            }

            trace_print(e, prefix, current_time_ns, 0);
        }
    }
    buffered_count = 0;
}

static unsigned long long get_ktime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -m, --msr        Trace MSR instructions\n");
    fprintf(stderr, "  -c, --cpuid      Trace CPUID instructions\n");
    fprintf(stderr, "  -i, --io         Trace IO port instructions (IN/OUT)\n");
    fprintf(stderr, "  -d, --dedupe     Deduplicate events\n");
    fprintf(stderr, "  -v, --verbose    Log MTRR and Machine Check MSRs\n");
    fprintf(stderr, "  -f, --filter     Only trace specific MSRs (can be used multiple times, e.g., -f 0x10 -f 0x3a)\n");
    fprintf(stderr, "  -h, --help       Show this help message\n");
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int flags = 0;
    #define MAX_FILTER_MSRS 256
    unsigned int filter_msrs[MAX_FILTER_MSRS];
    int filter_msrs_count = 0;
    int err;
    static struct option long_options[] = {
        {"dedupe", no_argument, 0, 'd'},
        {"msr", no_argument, 0, 'm'},
        {"cpuid", no_argument, 0, 'c'},
        {"io", no_argument, 0, 'i'},
        {"verbose", no_argument, 0, 'v'},
        {"filter", required_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "dmcivhf:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd': dedupe_mode = 1; break;
        case 'm': flags |= TRACE_MSR; break;
        case 'c': flags |= TRACE_CPUID; break;
        case 'i': flags |= TRACE_IO; break;
        case 'v': verbose = 1; break;
        case 'f':
            if (filter_msrs_count < MAX_FILTER_MSRS) {
                filter_msrs[filter_msrs_count++] = strtoul(optarg, NULL, 0);
            } else {
                fprintf(stderr, "Too many MSR filters specified (max %d)\n", MAX_FILTER_MSRS);
                return 1;
            }
            break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    if (flags == 0) {
        usage(argv[0]);
        return 1;
    }
    libbpf_set_print(NULL);

    rb = trace_init_rb(handle_event, flags, verbose);
    if (!rb) return 1;

    if (filter_msrs_count > 0) {
        trace_apply_filters(filter_msrs, filter_msrs_count);
    }

    /* Set up signal handlers for clean terminal restore */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (dedupe_mode && isatty(STDOUT_FILENO)) {
        enter_raw_mode();
        enter_alt_screen();
        atexit(restore_terminal);
    } else {
        printf("Tracing...\n");
    }

    int dropped_fd = trace_get_dropped_fd();
    unsigned long long last_print_ts = get_ktime_ns();
    int rb_fd = ring_buffer__epoll_fd(rb);

    while (!got_signal) {
        /* Poll both stdin (for keyboard) and BPF ring buffer */
        struct pollfd fds[2];
        int nfds = 0;

        fds[0].fd = rb_fd;
        fds[0].events = POLLIN;
        nfds = 1;

        if (dedupe_mode && isatty(STDIN_FILENO)) {
            fds[1].fd = STDIN_FILENO;
            fds[1].events = POLLIN;
            nfds = 2;
        }

        int poll_ret = poll(fds, nfds, 10);
        if (poll_ret < 0) {
            if (got_signal) break;
            continue;
        }

        /* Handle keyboard input */
        if (nfds > 1 && (fds[1].revents & POLLIN)) {
            if (handle_keyboard()) break;
        }

        /* Consume BPF events */
        err = ring_buffer__consume(rb);
        if (err < 0 && !got_signal) break;

        unsigned long long now = get_ktime_ns();
        if ((now - last_print_ts) > 200000000ULL) {
            flush_events(now);
            last_print_ts = now;
        }

        if (userspace_drops > 0) {
            flush_events(now);
            restore_terminal();
            fprintf(stderr, "\nError: Lost %llu events (userspace buffer full)\n", userspace_drops);
            break;
        }

        __u32 key = 0;
        __u64 val = 0;
        if (dropped_fd >= 0 && bpf_map_lookup_elem(dropped_fd, &key, &val) == 0) {
            if (val > 0) {
                restore_terminal();
                fprintf(stderr, "\nError: Lost %llu events (ring buffer full)\n", (unsigned long long)val);
                break;
            }
        }
    }

    restore_terminal();
    trace_cleanup();
    return 0;
}