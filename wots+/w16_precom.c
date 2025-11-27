#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "sha256.h"

// 配置参数（修改为w=16，中间值间隔8）
#define n 32          // 哈希长度（字节）
#define w 16          // 链参数（2的幂）
#define MSG_LEN 64    // 随机消息长度（字节）
#define BENCH_ROUNDS 10 // 基准测试轮数
#define MIDDLE_STEP 4  // 中间值间隔（每隔8个点取一个值）

// 派生参数（根据w=16重新计算）
#define log2w 4       // log2(w) = 4 （因为16=2^4）
#define l1 ((n * 8 + log2w - 1) / log2w) // 消息块数量
#define l2 ((32 - __builtin_clz(l1 * (w - 1)) + log2w - 1) / log2w) // 校验和块数量
#define l (l1 + l2)   // 总链数
#define MIDDLE_COUNT (((w - 1) + MIDDLE_STEP - 1) / MIDDLE_STEP + 1) // 每条链的中间值数量

// 类型定义
typedef uint8_t hash_t[n];
typedef hash_t wots_private_key[l];
typedef hash_t wots_public_key[l];
typedef hash_t wots_signature[l];
typedef hash_t wots_middle_values[l][MIDDLE_COUNT]; // 中间值存储

// 全局哈希迭代计数器
static unsigned long long hash_iteration_count = 0;

// 生成加密安全随机数
static void secure_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) { perror("Failed to open /dev/urandom"); exit(EXIT_FAILURE); }
    ssize_t ret = read(fd, buf, len);
    if (ret != (ssize_t)len) { perror("Failed to read random data"); close(fd); exit(EXIT_FAILURE); }
    close(fd);
}

// 带计数的哈希链计算
static void chain(hash_t x, int t, hash_t result) {
    memcpy(result, x, n);
    for (int i = 0; i < t; i++) {
        sha256(result, n, result);
        hash_iteration_count++;
    }
}

// 生成WOTS+密钥对（含中间值）
void wots_keygen(wots_private_key sk, wots_public_key pk, wots_middle_values middle,
                double *time_ms, unsigned long long *iterations) {
    // 生成私钥
    for (int i = 0; i < l; i++) {
        secure_random(sk[i], n);
    }

    // 计算公钥和中间值
    hash_iteration_count = 0;
    clock_t start = clock();
    
    for (int chain_idx = 0; chain_idx < l; chain_idx++) {
        // 存储第一个中间值（0次迭代 - 私钥本身）
        memcpy(middle[chain_idx][0], sk[chain_idx], n);
        
        // 计算后续中间值
        hash_t current;
        memcpy(current, sk[chain_idx], n);
        for (int m_idx = 1; m_idx < MIDDLE_COUNT; m_idx++) {
            int prev_step = (m_idx - 1) * MIDDLE_STEP;
            // 计算当前中间值的目标步骤（上限为w-1）
            int curr_step = m_idx * MIDDLE_STEP;
            if (curr_step > w - 1) curr_step = w - 1;
            
            int steps = curr_step - prev_step;  // 中间值之间的精确步骤数
            chain(current, steps, current);
            memcpy(middle[chain_idx][m_idx], current, n);
        }
        
        // 公钥是最后一个中间值（w-1次迭代）
        memcpy(pk[chain_idx], middle[chain_idx][MIDDLE_COUNT - 1], n);
    }
    
    clock_t end = clock();
    *time_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    *iterations = hash_iteration_count;
}

// 消息编码
static void message_encode(const hash_t msg_hash, int *c) {
    uint8_t buffer[32];
    memcpy(buffer, msg_hash, n);
    int bits_used = 0;

    // 将消息哈希拆分为l1个块
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

    // 计算校验和
    int sum = 0;
    for (int i = 0; i < l1; i++) {
        sum += (w - 1) - c[i];
    }

    // 将校验和拆分为l2个块
    for (int i = 0; i < l2; i++) {
        c[l1 + i] = sum & (w - 1);
        sum >>= log2w;
    }
}

// 使用中间值生成签名
void wots_sign(const hash_t msg_hash, const wots_middle_values middle, wots_signature sig,
              double *time_ms, unsigned long long *iterations, unsigned long long *saved_iterations) {
    int c[l];
    message_encode(msg_hash, c);

    hash_iteration_count = 0;
    *saved_iterations = 0;
    clock_t start = clock();
    
    for (int chain_idx = 0; chain_idx < l; chain_idx++) {
        int target = c[chain_idx];
        
        // 找到最大的中间值索引 <= 目标值
        int m_idx = 0;
        while (m_idx + 1 < MIDDLE_COUNT && (m_idx + 1) * MIDDLE_STEP <= target) {
            m_idx++;
        }
        
        int base_iter = m_idx * MIDDLE_STEP;
        int remaining = target - base_iter;
        
        // 从中间值生成签名
        chain(middle[chain_idx][m_idx], remaining, sig[chain_idx]);
        
        // 统计节省的迭代次数
        *saved_iterations += (target - remaining);
    }
    
    clock_t end = clock();
    *time_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    *iterations = hash_iteration_count;
}

// 验证签名
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

// 生成随机消息
void generate_random_message(uint8_t *msg, size_t len) {
    secure_random(msg, len);
}

// 基准测试函数
void benchmark() {
    wots_private_key sk;
    wots_public_key pk;
    wots_middle_values middle;
    
    printf("WOTS+ Accelerated Implementation (with middle values) Benchmark\n");
    printf("Parameters: n=%d, w=%d, l=%d, message length=%d bytes, rounds=%d\n", 
           n, w, l, MSG_LEN, BENCH_ROUNDS);
    printf("Middle values: interval=%d, count per chain=%d\n\n", MIDDLE_STEP, MIDDLE_COUNT);
    
    // 密钥生成基准测试（含中间值）
    double keygen_time;
    unsigned long long keygen_iter;
    wots_keygen(sk, pk, middle, &keygen_time, &keygen_iter);
    
    // 累计统计变量
    double total_sign_time = 0, total_verify_time = 0;
    unsigned long long total_sign_iter = 0, total_verify_iter = 0, total_saved_iter = 0;
    int total_valid = 0;
    
    // 多轮签名和验证
    for (int round = 0; round < BENCH_ROUNDS; round++) {
        // 生成随机消息
        uint8_t msg[MSG_LEN];
        generate_random_message(msg, MSG_LEN);
        
        // 计算消息哈希
        hash_t msg_hash;
        sha256(msg, MSG_LEN, msg_hash);
        
        // 生成加速签名
        wots_signature sig;
        double sign_time;
        unsigned long long sign_iter, saved_iter;
        wots_sign(msg_hash, middle, sig, &sign_time, &sign_iter, &saved_iter);
        
        // 验证签名
        double verify_time;
        unsigned long long verify_iter;
        int valid = wots_verify(msg_hash, sig, pk, &verify_time, &verify_iter);
        
        // 累计统计
        total_sign_time += sign_time;
        total_verify_time += verify_time;
        total_sign_iter += sign_iter;
        total_verify_iter += verify_iter;
        total_saved_iter += saved_iter;
        total_valid += valid;
    }
    
    // 计算大小
    size_t sk_size = l * n;                        // 私钥大小
    size_t pk_size = l * n;                        // 公钥大小
    size_t sig_size = l * n;                       // 签名大小
    size_t middle_size = l * MIDDLE_COUNT * n;     // 中间值存储大小
    
    // 打印结果
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
