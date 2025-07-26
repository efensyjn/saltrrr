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
#include <getopt.h>

#define DEFAULT_TARGET_PREFIX "...efensyjn..."
#define DEFAULT_SALT_PREFIX ".E."
#define DEFAULT_SALT_TOTAL_LEN 16
#define CHARSET "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

typedef struct {
    unsigned long start_idx;
    unsigned long step;
    unsigned long end_idx;
    atomic_ulong* counter;
    atomic_int* stop_flag;
    atomic_int* found_flag;
    char* password;
    const char* target_prefix;
    int target_prefix_len;
    const char* salt_prefix;
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
    char full_salt[64];
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
            build_salt(args->salt_prefix, salt_body, full_salt);

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

            if (strncmp(last_dollar, args->target_prefix, args->target_prefix_len) == 0) {
                if (!atomic_exchange(args->stop_flag, 1)) {
                    printf("\n\n=== MATCH FOUND ===\nSalt: %s%s\nHash: %s\n", args->salt_prefix, salt_body, hash);
                    atomic_store(args->found_flag, 1);
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

int run_chunk(unsigned long chunk_start, unsigned long chunk_end, char *password, int num_threads, 
              const char* target_prefix, int target_prefix_len,
              const char* salt_prefix, int salt_body_len) {
    pthread_t threads[num_threads];
    worker_args_t args[num_threads];
    atomic_ulong counter = chunk_start;
    atomic_int stop_flag = 0;
    atomic_int found_flag = 0;

    cpu_set_t cpuset;
    for (int i = 0; i < num_threads; i++) {
        args[i].start_idx = chunk_start + i;
        args[i].step = num_threads;
        args[i].end_idx = chunk_end;
        args[i].counter = &counter;
        args[i].stop_flag = &stop_flag;
        args[i].found_flag = &found_flag;
        args[i].password = password;
        args[i].target_prefix = target_prefix;
        args[i].target_prefix_len = target_prefix_len;
        args[i].salt_prefix = salt_prefix;
        args[i].salt_body_len = salt_body_len;

        pthread_create(&threads[i], NULL, worker, &args[i]);

        CPU_ZERO(&cpuset);
        CPU_SET(i % num_threads, &cpuset);
        pthread_setaffinity_np(threads[i], sizeof(cpu_set_t), &cpuset);
    }

    unsigned long last_count = chunk_start;
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

            printf("\rChunk %lu-%lu: %lu (%.2f/s)   ",
                   chunk_start, chunk_end, current_count, smoothed_speed);
            fflush(stdout);
        }

        last_count = current_count;
        last_time = current_time;

        if (chunk_end > 0 && current_count >= chunk_end) {
            atomic_store(&stop_flag, 1);
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return atomic_load(&found_flag);
}

void print_help(const char* prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Distributed hash finder with configurable parameters\n\n");
    printf("Basic options:\n");
    printf("  -d, --device-id=N      Device ID (starts from 1, required)\n");
    printf("  -t, --total-devices=N  Total devices in cluster (default: 1)\n");
    printf("  -c, --chunk-size=N     Indices per chunk (default: 1000000)\n");
    printf("  -r, --start-round=N    Starting round (default: 0)\n");
    printf("  -e, --end-idx=N        Global end index (default: 0 = no limit)\n");
    printf("  -R, --resume=N         Resume from global index (default: 0)\n\n");
    printf("Hash parameters:\n");
    printf("  -T, --target=S         Target hash prefix (default: \"aaa\")\n");
    printf("  -S, --salt-prefix=S    Salt prefix (default: \"\")\n");
    printf("  -L, --salt-len=N       Total salt length (default: 16)\n");
    printf("  -h, --help             Show this help message\n\n");
    printf("Examples:\n");
    printf("  Single device with custom chunk: %s -d1 -c10000\n", prog_name);
    printf("  3-device cluster: %s -d1 -t3  (run on each device with IDs 1-3)\n", prog_name);
    printf("  Custom search: %s -d1 -T\"xyz\" -S\"abc\" -L20\n", prog_name);
    printf("  Resume search: %s -d1 -t3 -r5 -R1000000\n", prog_name);
}

int main(int argc, char* argv[]) {
    // Default configuration
    int device_id = 0;
    int total_devices = 1;
    unsigned long chunk_size = 1000000;
    unsigned long start_round = 0;
    unsigned long end_idx = 0;
    unsigned long resume_from = 0;
    const char* target_prefix = DEFAULT_TARGET_PREFIX;
    const char* salt_prefix = DEFAULT_SALT_PREFIX;
    int salt_total_len = DEFAULT_SALT_TOTAL_LEN;

    // Parse command-line arguments
    static struct option long_options[] = {
        {"device-id", required_argument, 0, 'd'},
        {"total-devices", required_argument, 0, 't'},
        {"chunk-size", required_argument, 0, 'c'},
        {"start-round", required_argument, 0, 'r'},
        {"end-idx", required_argument, 0, 'e'},
        {"target", required_argument, 0, 'T'},
        {"salt-prefix", required_argument, 0, 'S'},
        {"salt-len", required_argument, 0, 'L'},
        {"resume", required_argument, 0, 'R'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "d:t:c:r:e:T:S:L:R:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd': device_id = atoi(optarg); break;
            case 't': total_devices = atoi(optarg); break;
            case 'c': chunk_size = strtoul(optarg, NULL, 10); break;
            case 'r': start_round = strtoul(optarg, NULL, 10); break;
            case 'e': end_idx = strtoul(optarg, NULL, 10); break;
            case 'T': target_prefix = optarg; break;
            case 'S': salt_prefix = optarg; break;
            case 'L': salt_total_len = atoi(optarg); break;
            case 'R': resume_from = strtoul(optarg, NULL, 10); break;
            case 'h': print_help(argv[0]); return 0;
            default: print_help(argv[0]); return 1;
        }
    }

    // Validate device configuration
    if (device_id < 1) {
        fprintf(stderr, "Error: Device ID must be at least 1\n");
        print_help(argv[0]);
        return 1;
    }
    if (device_id > total_devices) {
        fprintf(stderr, "Error: Device ID (%d) exceeds total devices (%d)\n", device_id, total_devices);
        return 1;
    }
    if (salt_total_len <= strlen(salt_prefix)) {
        fprintf(stderr, "Error: Salt length (%d) must be greater than salt prefix length (%zu)\n",
                salt_total_len, strlen(salt_prefix));
        return 1;
    }

    char* password = getpass("Enter password to hash: ");
    if (!password) {
        fprintf(stderr, "Failed to read password\n");
        return 1;
    }

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads < 1) num_threads = 4;

    int target_prefix_len = strlen(target_prefix);
    int salt_body_len = salt_total_len - strlen(salt_prefix);

    printf("\n==== Configuration ====\n");
    printf("Device ID: %d/%d\n", device_id, total_devices);
    printf("Chunk size: %lu\n", chunk_size);
    printf("Start round: %lu\n", start_round);
    printf("Resume from: %lu\n", resume_from);
    printf("End index: %lu\n", end_idx);
    printf("Target prefix: \"%s\"\n", target_prefix);
    printf("Salt prefix: \"%s\"\n", salt_prefix);
    printf("Total salt length: %d\n", salt_total_len);
    printf("Threads: %d\n", num_threads);
    printf("======================\n\n");

    unsigned long round = start_round;
    int found = 0;

    while (!found) {
        // Calculate chunk boundaries for this device in this round
        unsigned long chunk_start = resume_from + (round * total_devices + (device_id - 1)) * chunk_size;
        unsigned long chunk_end = chunk_start + chunk_size - 1;
        
        // Adjust chunk_end if it exceeds global end index
        if (end_idx > 0 && chunk_end > end_idx) {
            chunk_end = end_idx;
        }
        
        // Skip chunks that are completely beyond end index
        if (end_idx > 0 && chunk_start > end_idx) {
            printf("No more chunks available beyond index %lu\n", end_idx);
            break;
        }

        printf("\n=== Round %lu ===\n", round);
        printf("Processing chunk: %lu - %lu\n", chunk_start, chunk_end);
        
        found = run_chunk(chunk_start, chunk_end, password, num_threads, 
                          target_prefix, target_prefix_len,
                          salt_prefix, salt_body_len);

        if (found) {
            printf("\nMatch found by device %d!\n", device_id);
            break;
        }

        // Check if we've reached the end index
        if (end_idx > 0 && chunk_end >= end_idx) {
            printf("Reached global end index %lu\n", end_idx);
            break;
        }

        round++;
    }

    printf("\nDevice %d: Work completed\n", device_id);
    return 0;
}