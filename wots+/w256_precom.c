#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "sha256.h"

// Configuration parameters
#define n 32          // Hash length in bytes
#define w 256         // Chain parameter (power of 2)
#define MSG_LEN 64    // Random message length in bytes
#define BENCH_ROUNDS 10 // Number of benchmark rounds
#define MIDDLE_STEP 16 // Middle value interval

// Derived parameters
#define log2w 8       // log2(w) = 8 for w=256
#define l1 ((n * 8 + log2w - 1) / log2w) // Number of message blocks
#define l2 ((32 - __builtin_clz(l1 * (w - 1)) + log2w - 1) / log2w) // Number of checksum blocks
#define l (l1 + l2)   // Total number of chains
#define MIDDLE_COUNT (((w - 1) + MIDDLE_STEP - 1) / MIDDLE_STEP + 1) // Number of middle values per chain

// Type definitions
typedef uint8_t hash_t[n];
typedef hash_t wots_private_key[l];
typedef hash_t wots_public_key[l];
typedef hash_t wots_signature[l];
typedef hash_t wots_middle_values[l][MIDDLE_COUNT]; // Middle values storage

// Global hash iteration counter
static unsigned long long hash_iteration_count = 0;

// Generate cryptographically secure random numbers
static void secure_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) { perror("Failed to open /dev/urandom"); exit(EXIT_FAILURE); }
    ssize_t ret = read(fd, buf, len);
    if (ret != (ssize_t)len) { perror("Failed to read random data"); close(fd); exit(EXIT_FAILURE); }
    close(fd);
}

// Hash chain computation with iteration counting
static void chain(hash_t x, int t, hash_t result) {
    memcpy(result, x, n);
    for (int i = 0; i < t; i++) {
        sha256(result, n, result);
        hash_iteration_count++;
    }
}

// Generate WOTS+ key pair with middle values
void wots_keygen(wots_private_key sk, wots_public_key pk, wots_middle_values middle,
                double *time_ms, unsigned long long *iterations) {
    // Generate private key
    for (int i = 0; i < l; i++) {
        secure_random(sk[i], n);
    }

    // Compute public key and middle values
    hash_iteration_count = 0;
    clock_t start = clock();
    
    for (int chain_idx = 0; chain_idx < l; chain_idx++) {
        // Store first middle value (0 iterations - private key itself)
        memcpy(middle[chain_idx][0], sk[chain_idx], n);
        
        // Compute subsequent middle values
        hash_t current;
        memcpy(current, sk[chain_idx], n);
        // In wots_keygen function:
for (int m_idx = 1; m_idx < MIDDLE_COUNT; m_idx++) {
    int prev_step = (m_idx - 1) * MIDDLE_STEP;
    // Calculate target step for current middle value (capped at w-1)
    int curr_step = m_idx * MIDDLE_STEP;
    if (curr_step > w - 1) curr_step = w - 1;
    
    int steps = curr_step - prev_step;  // Exact steps between middle values
    chain(current, steps, current);
    memcpy(middle[chain_idx][m_idx], current, n);
}
        
        // Public key is the last middle value (w-1 iterations)
        memcpy(pk[chain_idx], middle[chain_idx][MIDDLE_COUNT - 1], n);
    }
    
    clock_t end = clock();
    *time_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    *iterations = hash_iteration_count;
}

// Message encoding
static void message_encode(const hash_t msg_hash, int *c) {
    uint8_t buffer[32];
    memcpy(buffer, msg_hash, n);
    int bits_used = 0;

    // Split message hash into l1 blocks
    for (int i = 0; i < l1; i++) {
        c[i] = 0;
        for (int j = 0; j < log2w; j++) {
            if (bits_used >= n * 8) break;
            uint8_t byte = buffer[bits_used / 8];
            uint8_t bit = (byte >> (7 - (bits_used % 8))) & 1;
            c[i] |= (bit << (log2w - 1 - j));
            bits_used++;
        }
    }

    // Compute checksum
    int sum = 0;
    for (int i = 0; i < l1; i++) {
        sum += (w - 1) - c[i];
    }

    // Split checksum into l2 blocks
    for (int i = 0; i < l2; i++) {
        c[l1 + i] = sum & (w - 1);
        sum >>= log2w;
    }
}

// Generate signature using middle values
void wots_sign(const hash_t msg_hash, const wots_middle_values middle, wots_signature sig,
              double *time_ms, unsigned long long *iterations, unsigned long long *saved_iterations) {
    int c[l];
    message_encode(msg_hash, c);

    hash_iteration_count = 0;
    *saved_iterations = 0;
    clock_t start = clock();
    
    for (int chain_idx = 0; chain_idx < l; chain_idx++) {
        int target = c[chain_idx];
        
        // Find the largest middle value index <= target
        int m_idx = 0;
        while (m_idx + 1 < MIDDLE_COUNT && (m_idx + 1) * MIDDLE_STEP <= target) {
            m_idx++;
        }
        
        int base_iter = m_idx * MIDDLE_STEP;
        int remaining = target - base_iter;
        
        // Generate signature from middle value
        chain(middle[chain_idx][m_idx], remaining, sig[chain_idx]);
        
        // Count saved iterations
        *saved_iterations += (target - remaining);
    }
    
    clock_t end = clock();
    *time_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    *iterations = hash_iteration_count;
}

// Verify signature (same as original)
int wots_verify(const hash_t msg_hash, const wots_signature sig, const wots_public_key pk,
               double *time_ms, unsigned long long *iterations) {
    int c[l];
    message_encode(msg_hash, c);
    hash_t computed_pk[l];

    hash_iteration_count = 0;
    clock_t start = clock();
    
    for (int i = 0; i < l; i++) {
        chain(sig[i], (w - 1) - c[i], computed_pk[i]);
        if (memcmp(computed_pk[i], pk[i], n) != 0) {
            *time_ms = 0;
            *iterations = 0;
            return 0;
        }
    }
    
    clock_t end = clock();
    *time_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    *iterations = hash_iteration_count;
    return 1;
}

// Generate random message
void generate_random_message(uint8_t *msg, size_t len) {
    secure_random(msg, len);
}

// Benchmark function
void benchmark() {
    wots_private_key sk;
    wots_public_key pk;
    wots_middle_values middle;
    
    printf("WOTS+ Accelerated Implementation (with middle values) Benchmark\n");
    printf("Parameters: n=%d, w=%d, l=%d, message length=%d bytes, rounds=%d\n", 
           n, w, l, MSG_LEN, BENCH_ROUNDS);
    printf("Middle values: interval=%d, count per chain=%d\n\n", MIDDLE_STEP, MIDDLE_COUNT);
    
    // Key generation benchmark (includes middle values)
    double keygen_time;
    unsigned long long keygen_iter;
    wots_keygen(sk, pk, middle, &keygen_time, &keygen_iter);
    
    // Variables for accumulated statistics
    double total_sign_time = 0, total_verify_time = 0;
    unsigned long long total_sign_iter = 0, total_verify_iter = 0, total_saved_iter = 0;
    int total_valid = 0;
    
    // Multi-round signature and verification
    for (int round = 0; round < BENCH_ROUNDS; round++) {
        // Generate random message
        uint8_t msg[MSG_LEN];
        generate_random_message(msg, MSG_LEN);
        
        // Compute message hash
        hash_t msg_hash;
        sha256(msg, MSG_LEN, msg_hash);
        
        // Generate signature with acceleration
        wots_signature sig;
        double sign_time;
        unsigned long long sign_iter, saved_iter;
        wots_sign(msg_hash, middle, sig, &sign_time, &sign_iter, &saved_iter);
        
        // Verify signature
        double verify_time;
        unsigned long long verify_iter;
        int valid = wots_verify(msg_hash, sig, pk, &verify_time, &verify_iter);
        
        // Accumulate statistics
        total_sign_time += sign_time;
        total_verify_time += verify_time;
        total_sign_iter += sign_iter;
        total_verify_iter += verify_iter;
        total_saved_iter += saved_iter;
        total_valid += valid;
    }
    
    // Calculate sizes
    size_t sk_size = l * n;                        // Private key size
    size_t pk_size = l * n;                        // Public key size
    size_t sig_size = l * n;                       // Signature size
    size_t middle_size = l * MIDDLE_COUNT * n;     // Middle values storage size
    
    // Print results
    printf("Benchmark Results (Average over %d rounds)\n", BENCH_ROUNDS);
    printf("1. Key Generation (with middle values):\n");
    printf("   - Hash iterations: %llu\n", keygen_iter);
    printf("   - Time: %.2f ms\n", keygen_time);
    printf("2. Signature Generation (accelerated):\n");
    printf("   - Average hash iterations: %llu\n", total_sign_iter / BENCH_ROUNDS);
    printf("   - Average time: %.2f ms\n", total_sign_time / BENCH_ROUNDS);
    printf("   - Average saved iterations: %llu\n", total_saved_iter / BENCH_ROUNDS);
    printf("3. Signature Verification:\n");
    printf("   - Average hash iterations: %llu\n", total_verify_iter / BENCH_ROUNDS);
    printf("   - Average time: %.2f ms\n", total_verify_time / BENCH_ROUNDS);
    printf("   - Verification success rate: %.0f%%\n", (double)total_valid / BENCH_ROUNDS * 100);
    printf("4. Sizes:\n");
    printf("   - Private key: %zu bytes\n", sk_size);
    printf("   - Public key: %zu bytes\n", pk_size);
    printf("   - Signature: %zu bytes\n", sig_size);
    printf("   - Middle values storage: %zu bytes\n", middle_size);
}

int main() {
    benchmark();
    return 0;
}
