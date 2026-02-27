#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include "trace.h"

#define MAX_SEEN_INDICES 4096
static unsigned int seen_indices[MAX_SEEN_INDICES];
static int seen_count = 0;

#define MAX_BUFFERED_EVENTS 100000
static struct event buffered_events[MAX_BUFFERED_EVENTS];
static int buffered_count = 0;
static unsigned long long userspace_drops = 0;
static int dedupe_mode = 0;

static struct event unique_events[MAX_SEEN_INDICES];
static int unique_count = 0;

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

        int is_tty = isatty(STDOUT_FILENO);
        if (is_tty) {
            printf("\033[2J\033[H");
        }

        struct winsize w;
        int max_rows = unique_count;
        if (is_tty && ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1 && w.ws_row > 1) {
            if (max_rows > w.ws_row - 1)
                max_rows = w.ws_row - 1;
        }

        for (int i = 0; i < (is_tty ? max_rows : unique_count); i++) {
            trace_print(&unique_events[i], '*', current_time_ns);
        }
    } else {
        for (int i = 0; i < buffered_count; i++) {
            struct event *e = &buffered_events[i];
            char prefix = '*';

            if (is_seen(e->index)) {
                prefix = ' ';
            } else {
                mark_seen(e->index);
            }

            trace_print(e, prefix, current_time_ns);
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

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int err;
    static struct option long_options[] = {{"dedupe", no_argument, 0, 'd'}, {0, 0, 0, 0}};
    int opt;
    while ((opt = getopt_long(argc, argv, "d", long_options, NULL)) != -1) {
        if (opt == 'd') dedupe_mode = 1;
    }

    libbpf_set_print(NULL);

    rb = trace_init_rb(handle_event);
    if (!rb) return 1;

    printf("Tracing...\n");
    int dropped_fd = trace_get_dropped_fd();
    unsigned long long last_print_ts = get_ktime_ns();

    while (1) {
        err = ring_buffer__poll(rb, 10);
        if (err < 0) break;
        
        ring_buffer__consume(rb);

        unsigned long long now = get_ktime_ns();
        if ((now - last_print_ts) > 200000000ULL) {
            flush_events(now);
            last_print_ts = now;
        }

        if (userspace_drops > 0) {
            flush_events(now);
            fprintf(stderr, "\nError: Lost %llu events (userspace buffer full)\n", userspace_drops);
            break;
        }
    }
    trace_cleanup();
    return 0;
}