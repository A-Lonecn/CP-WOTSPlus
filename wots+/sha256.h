#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stdlib.h>

// SHA256上下文结构
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

// 初始化SHA256上下文
void sha256_init(SHA256_CTX *ctx);

// 更新SHA256上下文（输入数据）
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);

// 完成哈希计算并输出结果
void sha256_final(SHA256_CTX *ctx, uint8_t *hash);

// 便捷函数：直接对数据进行SHA256哈希
void sha256(const uint8_t *data, size_t len, uint8_t *hash);

#endif // SHA256_H
