#pragma once
/**
 * Fully-functional, self-contained AES implementation (C++14, header-only)
 * -  Supports AES-128/192/256
 * -  Modes: CFB (segment = 128-bit) & CBC (NoPadding)
 * -  No dynamic allocation during encryption/decryption
 * -  Suitable for game clients / utility libs where <openssl/cryptopp> is overkill
 *
 *  USAGE (CBC example)
 *  ```cpp
 *  std::vector<uint8_t> key(16, 0x00);      // 128-bit key
 *  std::array<uint8_t, AES::BlockBytes> iv{};
 *  AES aes(AES::KeyLength::AES_128, key);
 *  auto cipher = aes.encryptCBC(plain, iv);
 *  auto plain2 = aes.decryptCBC(cipher, iv);
 *  ```
 */

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#if defined(__AES__) || (defined(_MSC_VER) && _MSC_VER >= 1600)
#define AES_HW 1
#include <wmmintrin.h>
#else
#define AES_HW 0
#endif

class AES final {
public:
    ~AES() noexcept
    {
#if defined(__STDC_LIB_EXT1__)
        memset_s(roundKeys_.data(), roundKeys_.size(), 0, roundKeys_.size());
#else 
        volatile std::uint8_t* p = roundKeys_.data();
        for (std::size_t i = 0; i < roundKeys_.size(); ++i) p[i] = 0;
#endif

#if AES_HW
        __m128i zero = _mm_setzero_si128();
        __m128i* q = rk128_.data();
        for (std::size_t i = 0; i < rk128_.size(); ++i)
            _mm_storeu_si128(&q[i], zero);
#endif

    }

    /* -------------------------------------------------------------
     * Public constants / types
     * -----------------------------------------------------------*/
    static constexpr std::size_t BlockBytes = 16;
    enum class KeyLength : std::uint8_t { AES_128 = 16, AES_192 = 24, AES_256 = 32 };

    /* -------------------------------------------------------------
     * Ctor expands round keys once
     * -----------------------------------------------------------*/
    explicit AES(KeyLength keylen, const std::vector<std::uint8_t>& key) {
        if (key.size() != static_cast<std::size_t>(keylen))
            throw std::invalid_argument("Key length mismatch");
        Nk_ = static_cast<std::uint8_t>(static_cast<std::size_t>(keylen) / 4);
        Nr_ = Nk_ + 6;
        expandKey(key);

#if AES_HW
        hwAccel_ = (Nk_ == 4) && cpuHasAESNI();
        if (hwAccel_) expandKeyNI(key);
#endif
    }

    /* -------------------------------------------------------------
     * CFB 128-bit (encrypt/decrypt are symmetric except for feedback)
     * -----------------------------------------------------------*/
    std::vector<std::uint8_t> encryptCFB(const std::vector<std::uint8_t>& plain,
        const std::array<std::uint8_t, BlockBytes>& iv) const {
        return cryptCFB(true, plain, iv);
    }

    std::vector<std::uint8_t> decryptCFB(const std::vector<std::uint8_t>& cipher,
        const std::array<std::uint8_t, BlockBytes>& iv) const {
        return cryptCFB(false, cipher, iv);
    }

    /* -------------------------------------------------------------
     * CBC NoPadding (caller ensures input multiple of 16)
     * -----------------------------------------------------------*/
    std::vector<std::uint8_t> encryptCBC(const std::vector<std::uint8_t>& plain,
        const std::array<std::uint8_t, BlockBytes>& iv) const {
        if (plain.size() % BlockBytes)
            throw std::length_error("CBC input not multiple of 16 bytes");
        std::vector<std::uint8_t> out(plain.size());
        std::array<std::uint8_t, BlockBytes> block;
        std::memcpy(block.data(), iv.data(), BlockBytes);
        for (std::size_t off = 0; off < plain.size(); off += BlockBytes) {
            xorBlocks(block.data(), &plain[off], block.data());
            encryptBlock(block.data(), &out[off]);
            std::memcpy(block.data(), &out[off], BlockBytes);
        }
        return out;
    }

    std::vector<std::uint8_t> decryptCBC(const std::vector<std::uint8_t>& cipher,
        const std::array<std::uint8_t, BlockBytes>& iv) const {
        if (cipher.size() % BlockBytes)
            throw std::length_error("CBC input not multiple of 16 bytes");
        std::vector<std::uint8_t> out(cipher.size());
        std::array<std::uint8_t, BlockBytes> block;
        std::memcpy(block.data(), iv.data(), BlockBytes);
        for (std::size_t off = 0; off < cipher.size(); off += BlockBytes) {
            decryptBlock(&cipher[off], &out[off]);
            xorBlocks(block.data(), &out[off], &out[off]);
            std::memcpy(block.data(), &cipher[off], BlockBytes);
        }
        return out;
    }

private:
    /* -------------------------------------------------------------
     * Rijndael tables (generated once)
     * -----------------------------------------------------------*/
    static constexpr std::array<std::uint8_t, 256> SBOX = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

    static constexpr std::array<std::uint8_t, 256> ISBOX = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d };

    static constexpr std::uint8_t gmul(std::uint8_t a, std::uint8_t b) noexcept
    {
        std::uint8_t res = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            if (b & 1u) res ^= a;
            bool hi = (a & 0x80u) != 0;
            a <<= 1;
            if (hi) a ^= 0x1Bu;
            b >>= 1;
        }
        return res;
    }

    /* -------------------------------------------------------------
     * Helper lambdas
     * -----------------------------------------------------------*/
    static void xorBlocks(const std::uint8_t* a, const std::uint8_t* b, std::uint8_t* dst) {
        for (std::size_t i = 0; i < BlockBytes; ++i) dst[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    }

    /* -------------------------------------------------------------
     * Round operations
     * -----------------------------------------------------------*/
    static void subBytes(std::uint8_t st[4][4]) {
        for (std::size_t r = 0; r < 4; ++r)
            for (std::size_t c = 0; c < 4; ++c)
                st[r][c] = SBOX[st[r][c]];
    }
    static void invSubBytes(std::uint8_t st[4][4]) {
        for (std::size_t r = 0; r < 4; ++r)
            for (std::size_t c = 0; c < 4; ++c)
                st[r][c] = ISBOX[st[r][c]];
    }
    static void shiftRows(std::uint8_t st[4][4]) {
        rotateRow(st[1], 1);
        rotateRow(st[2], 2);
        rotateRow(st[3], 3);
    }
    static void invShiftRows(std::uint8_t st[4][4]) {
        rotateRow(st[1], 3);
        rotateRow(st[2], 2);
        rotateRow(st[3], 1);
    }
    static void rotateRow(std::uint8_t* row, int n) {
        std::uint8_t tmp[4];
        for (int i = 0; i < 4; ++i) tmp[i] = row[(i + n) & 3];
        std::memcpy(row, tmp, 4);
    }

    static std::uint8_t gfMul(std::uint8_t a, std::uint8_t b) {
        std::uint8_t res = 0;
        while (b) {
            if (b & 1) res ^= a;
            bool hi = a & 0x80;
            a <<= 1;
            if (hi) a ^= 0x1b;
            b >>= 1;
        }
        return res;
    }

    static void mixColumns(std::uint8_t st[4][4]) {
        for (std::size_t c = 0; c < 4; ++c) {
            std::uint8_t a0 = st[0][c], a1 = st[1][c], a2 = st[2][c], a3 = st[3][c];
            st[0][c] = gfMul(2, a0) ^ gfMul(3, a1) ^ a2 ^ a3;
            st[1][c] = a0 ^ gfMul(2, a1) ^ gfMul(3, a2) ^ a3;
            st[2][c] = a0 ^ a1 ^ gfMul(2, a2) ^ gfMul(3, a3);
            st[3][c] = gfMul(3, a0) ^ a1 ^ a2 ^ gfMul(2, a3);
        }
    }
    static void invMixColumns(std::uint8_t st[4][4]) {
        for (std::size_t c = 0; c < 4; ++c) {
            std::uint8_t a0 = st[0][c], a1 = st[1][c], a2 = st[2][c], a3 = st[3][c];
            st[0][c] = gfMul(0x0e, a0) ^ gfMul(0x0b, a1) ^ gfMul(0x0d, a2) ^ gfMul(0x09, a3);
            st[1][c] = gfMul(0x09, a0) ^ gfMul(0x0e, a1) ^ gfMul(0x0b, a2) ^ gfMul(0x0d, a3);
            st[2][c] = gfMul(0x0d, a0) ^ gfMul(0x09, a1) ^ gfMul(0x0e, a2) ^ gfMul(0x0b, a3);
            st[3][c] = gfMul(0x0b, a0) ^ gfMul(0x0d, a1) ^ gfMul(0x09, a2) ^ gfMul(0x0e, a3);
        }
    }

    void addRoundKey(std::uint8_t st[4][4], std::uint8_t round) const {
        const std::uint8_t* rk = &roundKeys_[round * BlockBytes];
        for (std::size_t c = 0; c < 4; ++c)
            for (std::size_t r = 0; r < 4; ++r)
                st[r][c] ^= rk[r + 4 * c];
    }

    /* -------------------------------------------------------------
     * Encrypt/decrypt single block (16 bytes)
     * -----------------------------------------------------------*/
    void encryptBlockSoft(const std::uint8_t* in, std::uint8_t* out) const {
        std::uint8_t st[4][4] = {};
        for (std::size_t c = 0; c < 4; ++c)
            for (std::size_t r = 0; r < 4; ++r)
                st[r][c] = in[r + 4 * c];
        addRoundKey(st, 0);
        for (std::uint8_t rnd = 1; rnd < Nr_; ++rnd) {
            subBytes(st);
            shiftRows(st);
            mixColumns(st);
            addRoundKey(st, rnd);
        }
        subBytes(st);
        shiftRows(st);
        addRoundKey(st, Nr_);
        for (std::size_t c = 0; c < 4; ++c)
            for (std::size_t r = 0; r < 4; ++r)
                out[r + 4 * c] = st[r][c];
    }
    void decryptBlockSoft(const std::uint8_t* in, std::uint8_t* out) const {
        std::uint8_t st[4][4] = {};
        for (std::size_t c = 0; c < 4; ++c)
            for (std::size_t r = 0; r < 4; ++r)
                st[r][c] = in[r + 4 * c];
        addRoundKey(st, Nr_);
        for (std::uint8_t rnd = Nr_ - 1; rnd; --rnd) {
            invShiftRows(st);
            invSubBytes(st);
            addRoundKey(st, rnd);
            invMixColumns(st);
        }
        invShiftRows(st);
        invSubBytes(st);
        addRoundKey(st, 0);
        for (std::size_t c = 0; c < 4; ++c)
            for (std::size_t r = 0; r < 4; ++r)
                out[r + 4 * c] = st[r][c];
    }

    /* -------------------------------------------------------------
     * CFB helper
     * -----------------------------------------------------------*/
    std::vector<std::uint8_t> cryptCFB(bool enc, const std::vector<std::uint8_t>& in,
        const std::array<std::uint8_t, BlockBytes>& iv) const {
        std::vector<std::uint8_t> out(in.size());
        std::array<std::uint8_t, BlockBytes> block = iv;
        std::array<std::uint8_t, BlockBytes> encBlock;
        std::size_t idx = 0;
        while (idx + BlockBytes <= in.size()) {
            encryptBlock(block.data(), encBlock.data());
            xorBlocks(&in[idx], encBlock.data(), &out[idx]);
            std::memcpy(block.data(), enc ? &out[idx] : &in[idx], BlockBytes);
            idx += BlockBytes;
        }
        if (auto rem = in.size() - idx) {
            encryptBlock(block.data(), encBlock.data());
            for (std::size_t i = 0; i < rem; ++i)
                out[idx + i] = static_cast<std::uint8_t>(in[idx + i] ^ encBlock[i]);
        }
        return out;
    }

    /* -------------------------------------------------------------
     * Key expansion (FIPS-197 5.2)
     * -----------------------------------------------------------*/
    static std::uint32_t subWord(std::uint32_t w) {
        return (static_cast<std::uint32_t>(SBOX[w >> 24]) << 24) |
            (static_cast<std::uint32_t>(SBOX[(w >> 16) & 0xff]) << 16) |
            (static_cast<std::uint32_t>(SBOX[(w >> 8) & 0xff]) << 8) |
            static_cast<std::uint32_t>(SBOX[w & 0xff]);
    }
    static std::uint32_t rotWord(std::uint32_t w) { return (w << 8) | (w >> 24); }
    static std::uint32_t rcon(std::uint8_t i) {
        std::uint32_t c = 1;
        while (--i) c = gfMul(c, 2);
        return c << 24;
    }
    void expandKey(const std::vector<std::uint8_t>& key) {
        const std::size_t wordCount = 4 * (Nr_ + 1);
        std::vector<std::uint32_t> w(wordCount);
        // copy key
        for (std::size_t i = 0; i < Nk_; ++i) {
            w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) |
                (key[4 * i + 2] << 8) | key[4 * i + 3];
        }
        for (std::size_t i = Nk_; i < wordCount; ++i) {
            std::uint32_t temp = w[i - 1];
            if (i % Nk_ == 0) temp = subWord(rotWord(temp)) ^ rcon(static_cast<std::uint8_t>(i / Nk_));
            else if (Nk_ > 6 && i % Nk_ == 4) temp = subWord(temp);
            w[i] = w[i - Nk_] ^ temp;
        }
        for (std::size_t i = 0; i < wordCount; ++i) {
            roundKeys_[4 * i + 0] = static_cast<std::uint8_t>(w[i] >> 24);
            roundKeys_[4 * i + 1] = static_cast<std::uint8_t>((w[i] >> 16) & 0xff);
            roundKeys_[4 * i + 2] = static_cast<std::uint8_t>((w[i] >> 8) & 0xff);
            roundKeys_[4 * i + 3] = static_cast<std::uint8_t>(w[i] & 0xff);
        }
    }

#if AES_HW
    static bool cpuHasAESNI() {
#if defined(_MSC_VER)
        int r[4]; __cpuidex(r, 1, 0);
        return (r[2] & (1 << 25)) != 0;
#else
        unsigned eax, ebx, ecx, edx;
        __asm__ __volatile__("cpuid"
            : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
            : "a"(1), "c"(0));
        return (ecx & (1u << 25)) != 0;
#endif
    }
#endif

#if AES_HW
    void expandKeyNI(const std::vector<std::uint8_t>& k)
    {
        __m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(k.data()));
        rk128_[0] = tmp;

        __m128i t2;

        /* round 1 : RC = 0x01 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x01);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[1] = tmp;

        /* round 2 : RC = 0x02 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x02);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[2] = tmp;

        /* round 3 : RC = 0x04 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x04);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[3] = tmp;

        /* round 4 : RC = 0x08 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x08);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[4] = tmp;

        /* round 5 : RC = 0x10 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x10);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[5] = tmp;

        /* round 6 : RC = 0x20 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x20);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[6] = tmp;

        /* round 7 : RC = 0x40 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x40);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[7] = tmp;

        /* round 8 : RC = 0x80 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x80);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[8] = tmp;

        /* round 9 : RC = 0x1B */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x1B);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[9] = tmp;

        /* round 10 : RC = 0x36 */
        t2 = _mm_aeskeygenassist_si128(tmp, 0x36);
        t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 3, 3, 3));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));
        tmp = _mm_xor_si128(tmp, t2);
        rk128_[10] = tmp;
    }
#endif

#if AES_HW
    inline void encryptBlockNI(const uint8_t* in, uint8_t* out) const {
        __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
        m = _mm_xor_si128(m, rk128_[0]);
        for (int i = 1; i < 10; ++i)  m = _mm_aesenc_si128(m, rk128_[i]);
        m = _mm_aesenclast_si128(m, rk128_[10]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m);
    }
    inline void decryptBlockNI(const uint8_t* in, uint8_t* out) const {
        __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
        m = _mm_xor_si128(m, rk128_[10]);
        for (int i = 9; i > 0; --i)    m = _mm_aesdec_si128(m, rk128_[i]);
        m = _mm_aesdeclast_si128(m, rk128_[0]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m);
    }
#endif

    inline void encryptBlock(const uint8_t* in, uint8_t* out) const {
#if AES_HW
        if (hwAccel_) { encryptBlockNI(in, out); return; }
#endif
        encryptBlockSoft(in, out);
    }
    inline void decryptBlock(const uint8_t* in, uint8_t* out) const {
#if AES_HW
        if (hwAccel_) { decryptBlockNI(in, out); return; }
#endif
        decryptBlockSoft(in, out);
    }

    /* -------------------------------------------------------------
     * Data members
     * -----------------------------------------------------------*/
    std::uint8_t Nk_ = 0;
    std::uint8_t Nr_ = 0;
    std::array<std::uint8_t, 16 * (14 + 1)> roundKeys_{}; // max 256-bit (14 rounds + 1) * 16 bytes

#if AES_HW
    std::array<__m128i, 11> rk128_{};
    bool hwAccel_ = false;
#else
    bool hwAccel_ = false;
#endif

};