// sha256.cpp
// Standalone SHA-256 implementation.
// Compile:
//   g++ -std=c++17 -O2 sha256.cpp -o sha256
//
// Usage:
//   ./sha256 filename.txt
// or
//   cat filename.txt | ./sha256

#include <bits/stdc++.h>
using namespace std;
using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

static inline u32 rotr(u32 x, unsigned n) { return (x >> n) | (x << (32 - n)); }

array<u8,32> sha256_bytes(const vector<u8>& data) {
    u32 h[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    const u32 k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };

    // Pre-processing (padding)
    u64 bitlen = (u64)data.size() * 8ULL;
    vector<u8> msg(data);
    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i) msg.push_back((u8)((bitlen >> (8*i)) & 0xFF));

    // Process each 512-bit chunk
    for (size_t off = 0; off < msg.size(); off += 64) {
        const u8* chunk = msg.data() + off;
        u32 w[64];
        // first 16 words
        for (int t = 0; t < 16; ++t) {
            w[t] = ((u32)chunk[4*t] << 24) | ((u32)chunk[4*t+1] << 16) | ((u32)chunk[4*t+2] << 8) | ((u32)chunk[4*t+3]);
        }
        // extend
        for (int t = 16; t < 64; ++t) {
            u32 s0 = rotr(w[t-15], 7) ^ rotr(w[t-15], 18) ^ (w[t-15] >> 3);
            u32 s1 = rotr(w[t-2], 17) ^ rotr(w[t-2], 19) ^ (w[t-2] >> 10);
            w[t] = w[t-16] + s0 + w[t-7] + s1;
        }
        // init working vars
        u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        // main loop
        for (int t = 0; t < 64; ++t) {
            u32 S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            u32 ch = (e & f) ^ ((~e) & g);
            u32 temp1 = hh + S1 + ch + k[t] + w[t];
            u32 S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            u32 maj = (a & b) ^ (a & c) ^ (b & c);
            u32 temp2 = S0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        // add compressed chunk
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    array<u8,32> digest;
    for (int i = 0; i < 8; ++i) {
        digest[4*i+0] = (u8)((h[i] >> 24) & 0xFF);
        digest[4*i+1] = (u8)((h[i] >> 16) & 0xFF);
        digest[4*i+2] = (u8)((h[i] >> 8) & 0xFF);
        digest[4*i+3] = (u8)(h[i] & 0xFF);
    }
    return digest;
}

string to_hex(const array<u8,32>& d) {
    static const char* hex = "0123456789abcdef";
    string s; s.reserve(64);
    for (u8 b : d) {
        s.push_back(hex[(b >> 4) & 0xF]);
        s.push_back(hex[b & 0xF]);
    }
    return s;
}

int main(int argc, char** argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    vector<u8> data;
    if (argc >= 2) {
        // read file
        ifstream ifs(argv[1], ios::binary);
        if (!ifs) {
            cerr << "Error: cannot open file '" << argv[1] << "'\n";
            return 2;
        }
        data.assign((istreambuf_iterator<char>(ifs)), istreambuf_iterator<char>());
    } else {
        // read stdin
        char buf[8192];
        while (cin.read(buf, sizeof(buf))) data.insert(data.end(), buf, buf + sizeof(buf));
        data.insert(data.end(), buf, buf + cin.gcount());
    }

    auto digest = sha256_bytes(data);
    cout << to_hex(digest) << "\n";
    return 0;
}
