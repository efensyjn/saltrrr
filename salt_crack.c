#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>

#define TARGET_PREFIX "efensyjn"
#define SALT_PREFIX "st4r"
#define SALT_TOTAL_LEN 16
#define CHARSET "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

typedef struct {
    unsigned long start_idx;
    unsigned long step;
    unsigned long end_idx;
    atomic_ulong* counter;
    atomic_int* stop_flag;
    char* password;
    int target_prefix_len;
    int salt_body_len;
} worker_args_t;

static inline void build_salt(const char* prefix, const char* salt_body, char* out) {
    char* p = out;
    *p++ = '$'; *p++ = '6'; *p++ = '$';
    while (*prefix) *p++ = *prefix++;
    while (*salt_body) *p++ = *salt_body++;
    *p++ = '$';
    *p = '\0';
}

static inline void index_to_salt(unsigned long index, int salt_body_len, char* output) {
    for (int i = salt_body_len - 1; i >= 0; i--) {
        output[i] = CHARSET[index & 63];
        index >>= 6;
    }
    output[salt_body_len] = '\0';
}

void* worker(void* arg) {
    worker_args_t* args = (worker_args_t*)arg;
    unsigned long idx = args->start_idx;
    char salt_body[args->salt_body_len + 1];
    char full_salt[32];
    struct crypt_data cdata;
    cdata.initialized = 0;

    unsigned long local_count = 0;
    const int batch_size = 1000;

    while (!atomic_load(args->stop_flag)) {
        for (int i = 0; i < batch_size; i++) {
            if (args->end_idx > 0 && idx > args->end_idx) {
                atomic_store(args->stop_flag, 1);
                return NULL;
            }

            index_to_salt(idx, args->salt_body_len, salt_body);
            build_salt(SALT_PREFIX, salt_body, full_salt);

            char* hash = crypt_r(args->password, full_salt, &cdata);
            if (!hash) {
                fprintf(stderr, "\ncrypt() failed\n");
                atomic_store(args->stop_flag, 1);
                return NULL;
            }

            char* last_dollar = strrchr(hash, '$');
            if (!last_dollar) {
                fprintf(stderr, "\nUnexpected hash format\n");
                atomic_store(args->stop_flag, 1);
                return NULL;
            }
            last_dollar++;

            if (strncmp(last_dollar, TARGET_PREFIX, args->target_prefix_len) == 0) {
                if (!atomic_exchange(args->stop_flag, 1)) {
                    printf("\n\n=== MATCH FOUND ===\nSalt: %s%s\nHash: %s\n", SALT_PREFIX, salt_body, hash);
                }
                return NULL;
            }

            idx += args->step;
            local_count++;
        }
        atomic_fetch_add(args->counter, local_count);
        local_count = 0;
    }

    return NULL;
}

int main(int argc, char* argv[]) {
    unsigned long resume_from = 0;
    unsigned long end_index = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--resume") == 0 && i + 1 < argc) {
            resume_from = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--end") == 0 && i + 1 < argc) {
            end_index = strtoull(argv[++i], NULL, 10);
        }
    }

    if (end_index > 0 && resume_from > end_index) {
        fprintf(stderr, "Error: resume point (%lu) is beyond end point (%lu)\n", resume_from, end_index);
        return 1;
    }

    char* password = getpass("Enter password to hash: ");
    if (!password) {
        fprintf(stderr, "Failed to read password\n");
        return 1;
    }

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads < 1) num_threads = 4;

    pthread_t threads[num_threads];
    worker_args_t args[num_threads];
    atomic_ulong counter = resume_from;
    atomic_int stop_flag = 0;

    int target_prefix_len = strlen(TARGET_PREFIX);
    int salt_body_len = SALT_TOTAL_LEN - strlen(SALT_PREFIX);

    printf("Starting with %d threads from %lu", num_threads, resume_from);
    if (end_index > 0)
        printf(" to %lu", end_index);
    printf("...\n");

    cpu_set_t cpuset;

    for (int i = 0; i < num_threads; i++) {
        args[i].start_idx = resume_from + i;
        args[i].step = num_threads;
        args[i].end_idx = end_index;
        args[i].counter = &counter;
        args[i].stop_flag = &stop_flag;
        args[i].password = password;
        args[i].target_prefix_len = target_prefix_len;
        args[i].salt_body_len = salt_body_len;

        pthread_create(&threads[i], NULL, worker, &args[i]);

        CPU_ZERO(&cpuset);
        CPU_SET(i % num_threads, &cpuset);
        pthread_setaffinity_np(threads[i], sizeof(cpu_set_t), &cpuset);
    }

    unsigned long last_count = resume_from;
    struct timespec last_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &last_time);

    double smoothed_speed = 0.0;
    const double alpha = 0.3;

    while (!atomic_load(&stop_flag)) {
        usleep(200000);

        clock_gettime(CLOCK_MONOTONIC, &current_time);
        unsigned long current_count = atomic_load(&counter);

        double elapsed = (current_time.tv_sec - last_time.tv_sec) +
                         (current_time.tv_nsec - last_time.tv_nsec) / 1e9;

        if (elapsed > 0) {
            double speed = (current_count - last_count) / elapsed;
            smoothed_speed = smoothed_speed == 0 ? speed : alpha * speed + (1 - alpha) * smoothed_speed;

            printf("\rTotal attempts: %lu (speed: %.2f attempts/s)   ",
                   current_count, smoothed_speed);
            fflush(stdout);
        }

        last_count = current_count;
        last_time = current_time;

        if (end_index > 0 && current_count >= end_index)
            atomic_store(&stop_flag, 1);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nDone.\n");
    return 0;
}
