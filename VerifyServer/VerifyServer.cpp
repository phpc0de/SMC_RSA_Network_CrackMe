// VerifyServer.cpp - 完整版，已包含所有依赖函数
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>
#pragma comment(lib, "ws2_32.lib")

// ========== SHA-256 完整实现 ==========
typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned long long bitlen;
    unsigned int state[8];
} SHA256_CTX;

static const unsigned int K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

void sha256_transform(SHA256_CTX* ctx, const unsigned char data[]) {
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX* ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a; ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX* ctx, const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX* ctx, unsigned char* hash) {
    unsigned int i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)ctx->data[i++] = 0;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)ctx->data[i++] = 0;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i] = (unsigned char)(ctx->state[0] >> (24 - i * 8));
        hash[i + 4] = (unsigned char)(ctx->state[1] >> (24 - i * 8));
        hash[i + 8] = (unsigned char)(ctx->state[2] >> (24 - i * 8));
        hash[i + 12] = (unsigned char)(ctx->state[3] >> (24 - i * 8));
        hash[i + 16] = (unsigned char)(ctx->state[4] >> (24 - i * 8));
        hash[i + 20] = (unsigned char)(ctx->state[5] >> (24 - i * 8));
        hash[i + 24] = (unsigned char)(ctx->state[6] >> (24 - i * 8));
        hash[i + 28] = (unsigned char)(ctx->state[7] >> (24 - i * 8));
    }
}

void sha256(const unsigned char* data, size_t len, unsigned char* out) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

// ========== RSA-1024 大数库 ==========
#define RSA_BITS 1024
#define RSA_BYTES (RSA_BITS/8)
#define BN_WORDS (RSA_BITS/32)

typedef struct {
    unsigned int d[BN_WORDS];
    int size;
} BigNum;

void bn_zero(BigNum* a) { memset(a, 0, sizeof(*a)); a->size = 0; }
void bn_set_word(BigNum* a, unsigned int w) {
    bn_zero(a);
    if (w) { a->d[0] = w; a->size = 1; }
}
int bn_cmp(const BigNum* a, const BigNum* b) {
    if (a->size != b->size) return (a->size > b->size) ? 1 : -1;
    for (int i = a->size - 1; i >= 0; i--)
        if (a->d[i] != b->d[i]) return (a->d[i] > b->d[i]) ? 1 : -1;
    return 0;
}
void bn_add(BigNum* r, const BigNum* a, const BigNum* b) {
    bn_zero(r);
    unsigned long long carry = 0;
    int max_size = (a->size > b->size) ? a->size : b->size;
    for (int i = 0; i < max_size || carry; i++) {
        unsigned long long sum = carry;
        if (i < a->size) sum += a->d[i];
        if (i < b->size) sum += b->d[i];
        r->d[i] = (unsigned int)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
    }
    r->size = (carry) ? max_size + 1 : max_size;
    while (r->size > 0 && r->d[r->size - 1] == 0) r->size--;
}
void bn_sub(BigNum* r, const BigNum* a, const BigNum* b) {
    bn_zero(r);
    long long borrow = 0;
    for (int i = 0; i < a->size; i++) {
        long long diff = (long long)a->d[i] - borrow;
        if (i < b->size) diff -= b->d[i];
        if (diff < 0) { diff += 0x100000000LL; borrow = 1; }
        else borrow = 0;
        r->d[i] = (unsigned int)(diff & 0xFFFFFFFF);
    }
    r->size = a->size;
    while (r->size > 0 && r->d[r->size - 1] == 0) r->size--;
}
void bn_mul(BigNum* r, const BigNum* a, const BigNum* b) {
    bn_zero(r);
    for (int i = 0; i < a->size; i++) {
        unsigned long long carry = 0;
        for (int j = 0; j < b->size; j++) {
            unsigned long long prod = (unsigned long long)a->d[i] * b->d[j] + r->d[i + j] + carry;
            r->d[i + j] = (unsigned int)(prod & 0xFFFFFFFF);
            carry = prod >> 32;
        }
        r->d[i + b->size] = (unsigned int)carry;
    }
    r->size = a->size + b->size;
    while (r->size > 0 && r->d[r->size - 1] == 0) r->size--;
}
void bn_mod(BigNum* r, const BigNum* a, const BigNum* mod) {
    BigNum tmp = *a;
    while (bn_cmp(&tmp, mod) >= 0) bn_sub(&tmp, &tmp, mod);
    *r = tmp;
}
void bn_mod_exp(BigNum* r, const BigNum* base, const BigNum* exp, const BigNum* mod) {
    bn_zero(r);
    r->d[0] = 1; r->size = 1;
    BigNum tmp;
    for (int i = exp->size - 1; i >= 0; i--) {
        unsigned int word = exp->d[i];
        for (int bit = 31; bit >= 0; bit--) {
            bn_mul(&tmp, r, r);
            bn_mod(r, &tmp, mod);
            if ((word >> bit) & 1) {
                bn_mul(&tmp, r, base);
                bn_mod(r, &tmp, mod);
            }
        }
    }
}
void bn_from_hex(BigNum* a, const char* hex) {
    bn_zero(a);
    size_t len = strlen(hex);
    for (size_t i = 0; i < len; i++) {
        BigNum mult; mult.d[0] = 16; mult.size = 1;
        bn_mul(a, a, &mult);
        char c = hex[i];
        unsigned int nibble;
        if (c >= '0' && c <= '9') nibble = c - '0';
        else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
        else continue;
        BigNum val; bn_set_word(&val, nibble);
        bn_add(a, a, &val);
    }
}

// RSA 公钥（与客户端一致）
static const char* RSA_N_HEX =
"D9B2E8C1C1B8F5C3A5E6D7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8"
"C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0"
"E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2"
"A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4";
static const unsigned int RSA_E = 65537;

int VerifyRSA(const char* name, const char* serial) {
    if (!name || !serial || strlen(name) < 3) return 0;

    unsigned char hash[32];
    sha256((const unsigned char*)name, strlen(name), hash);

    BigNum m;
    bn_zero(&m);
    for (int i = 0; i < 32; i++) {
        BigNum mult; mult.d[0] = 256; mult.size = 1;
        bn_mul(&m, &m, &mult);
        BigNum val; bn_set_word(&val, hash[i]);
        bn_add(&m, &m, &val);
    }

    BigNum sig;
    bn_from_hex(&sig, serial);

    BigNum n, e;
    bn_from_hex(&n, RSA_N_HEX);
    bn_zero(&e); e.d[0] = RSA_E; e.size = 1;

    BigNum expected;
    bn_mod_exp(&expected, &sig, &e, &n);

    return (bn_cmp(&m, &expected) == 0) ? 1 : 0;
}
// ========== HTTP 请求解析 ==========
int ParseRequest(const char* request, char* name, char* serial, DWORD* flags) {
    const char* body = strstr(request, "\r\n\r\n");
    if (!body) return 0;
    body += 4;

    const char* nameStart = strstr(body, "name=");
    const char* serialStart = strstr(body, "&serial=");
    const char* flagsStart = strstr(body, "&flags=");
    if (!nameStart || !serialStart) return 0;

    nameStart += 5;
    size_t nameLen = serialStart - nameStart;
    if (nameLen >= 128) nameLen = 127;
    memcpy(name, nameStart, nameLen);
    name[nameLen] = '\0';

    serialStart += 8;
    size_t serialLen = (flagsStart ? (flagsStart - serialStart) : strlen(serialStart));
    if (serialLen >= 1024) serialLen = 1023;
    memcpy(serial, serialStart, serialLen);
    serial[serialLen] = '\0';

    if (flagsStart) {
        *flags = (DWORD)atoi(flagsStart + 7);
    }
    else {
        *flags = 0;
    }
    return 1;
}

// ========== 控制台事件（处理窗口关闭） ==========
static volatile int running = 1;

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_CLOSE_EVENT) {
        running = 0;
        Sleep(1000);
        return TRUE;
    }
    return FALSE;
}

// ========== 主函数 ==========
int main() {
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(listenSocket, SOMAXCONN);

    printf("VerifyServer listening on 127.0.0.1:8080\n");
    printf("Press 'q' + Enter or close window to quit.\n");

    u_long nonBlock = 1;
    ioctlsocket(listenSocket, FIONBIO, &nonBlock);

    while (running) {
        if (_kbhit() && _getch() == 'q') running = 0;

        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);

        if (clientSocket != INVALID_SOCKET) {
            char buffer[2048];
            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesReceived > 0) {
                buffer[bytesReceived] = '\0';

                char name[128], serial[1024];
                DWORD flags = 0;
                if (ParseRequest(buffer, name, serial, &flags)) {
                    int valid = VerifyRSA(name, serial);
                    if (valid && flags == 0) {
                        printf("[RESULT] SUCCESS for name=%s\n", name);
                        const char* response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";
                        send(clientSocket, response, (int)strlen(response), 0);
                    }
                    else {
                        printf("[RESULT] DENIED for name=%s (valid=%d, flags=%u)\n", name, valid, flags);
                        const char* response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"status\":\"denied\"}";
                        send(clientSocket, response, (int)strlen(response), 0);
                    }
                }
                printf("[REQUEST] name=%s, serial=%s, flags=%u\n", name, serial, flags);
            }
            closesocket(clientSocket);
        }
        Sleep(10);
    }

    closesocket(listenSocket);
    WSACleanup();
    printf("Server shutdown complete.\n");
    return 0;
}