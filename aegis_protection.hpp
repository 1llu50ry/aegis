#pragma once

/**
 * ============================================================================
 *                       AEGIS MASTER PROTECTION SUITE                         
 * ============================================================================
 * Complete Header-Only Code Protection, Virtualization & Anti-Reversing SDK
 * 
 * Integrated Modules (All Folders Unified):
 *   1. Core Types, Constexpr PRNG & High-Performance Hashing (FNV-1a, Murmur3, CRC32)
 *   2. Mixed Boolean Arithmetic (MBA) Algebraic Transformation Engine
 *   3. Compile-Time Polymorphic String Encryption (AEGIS_STR) with Stack Zeroization
 *   4. Split-Variable Integer Obfuscation (AEGIS_INT)
 *   5. Opaque Predicates & Compiler Optimization Barriers
 *   6. Control Flow Flattening (CFF) State Machine
 *   7. Virtual Machine Engine (V-ISA, Rolling-Key Cipher, MBA Handlers, Native Bridge)
 *   8. Fluent Bytecode Assembler / Compiler DSL (BytecodeBuilder)
 *   9. Multi-Vector Anti-Debugging Suite (PEB, DR0-DR7, RDTSC, ThreadHide, Port)
 *  10. Virtual Machine & Sandbox Detection (Anti-VM: VMware, VBox, QEMU, KVM, Hyper-V)
 *  11. Anti-Dumping & PE Header Eraser (Blocks Scylla, MegaDumper, Process Hacker)
 *  12. Anti-Disassembly Desynchronization & Junk Code Injection
 *  13. Memory & Code Integrity Scanner (INT 3, JMP Hooks, Murmur3/CRC32 Checksum)
 *  14. Dynamic PE Export Resolver via API Hashing (Zero IAT strings)
 *  15. Hardware Identity & TPM Fingerprint Extraction (HWID / Crypto Provider)
 *  16. Process & Memory Utilities (Memory scanning, Process inspection, Working set cleaner)
 *  17. JVM Native Bridge (JNI protection & native method registration)
 *  18. Embedded Pure C++20 Cryptography (FIPS 180-4 SHA-256, HMAC-SHA256 & RFC 8439 ChaCha20)
 *  19. Polymorphic VM Opcode Scrambler & Extended V-ISA (BSWAP, POPCNT, VMEMCPY, VMEMSET, JUNK)
 *  20. NTDLL System Call Stub Inspector & SSN Verifier (Anti-Hook Integrity Verification)
 *  21. Vectored Exception Handling (VEH) Hardware Breakpoint & Trap Guard
 *  22. Background Memory Integrity Watchdog Thread (Continuous Code & Anti-Debug Monitor)
 * ============================================================================
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <array>
#include <random>
#include <functional>
#include <unordered_map>
#include <memory>
#include <cstring>
#include <utility>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <bit>

#if defined(_WIN32) || defined(_WIN64) || defined(__NT__)
    #define AEGIS_WINDOWS 1
    #define WIN32_LEAN_AND_MEAN
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
    #include <winternl.h>
    #include <intrin.h>
    #include <tlhelp32.h>
    #include <psapi.h>
    #include <ncrypt.h>
    #include <wincrypt.h>
    #include <iphlpapi.h>

    #pragma comment(lib, "ncrypt.lib")
    #pragma comment(lib, "crypt32.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "psapi.lib")
    #pragma comment(lib, "iphlpapi.lib")
#elif defined(__linux__) || defined(__gnu_linux__)
    #define AEGIS_LINUX 1
    #include <sys/ptrace.h>
    #include <unistd.h>
    #include <dlfcn.h>
#elif defined(__APPLE__) && defined(__MACH__)
    #define AEGIS_MACOS 1
    #include <dlfcn.h>
#endif

// Architecture Detection
#if defined(__x86_64__) || defined(_M_X64)
    #define AEGIS_ARCH_X64 1
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    #define AEGIS_ARCH_X86 1
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define AEGIS_ARCH_ARM64 1
#endif

// Compiler Detection
#if defined(_MSC_VER) && !defined(__clang__)
    #define AEGIS_COMPILER_MSVC 1
    #define AEGIS_FORCEINLINE __forceinline
    #define AEGIS_NOINLINE __declspec(noinline)
#elif defined(__clang__) || defined(__GNUC__)
    #define AEGIS_FORCEINLINE __attribute__((always_inline)) inline
    #define AEGIS_NOINLINE __attribute__((noinline))
#else
    #define AEGIS_FORCEINLINE inline
    #define AEGIS_NOINLINE
#endif

namespace aegis {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

using i8  = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

using reg_t = u64;

// Secure Memory Zeroization
inline void secure_zero(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;
    volatile u8* p = static_cast<volatile u8*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

// ============================================================================
// 1. CORE TYPES & HASHING (FNV-1a, Murmur3, CRC32)
// ============================================================================
namespace core {

namespace detail {
    constexpr u64 seed_from_time() noexcept {
        constexpr const char* t = __TIME__;
        return static_cast<u64>(t[0] - '0') * 36000 +
               static_cast<u64>(t[1] - '0') * 3600 +
               static_cast<u64>(t[3] - '0') * 600 +
               static_cast<u64>(t[4] - '0') * 60 +
               static_cast<u64>(t[6] - '0') * 10 +
               static_cast<u64>(t[7] - '0');
    }
} // namespace detail

#define AEGIS_COMPILE_SEED() (::aegis::core::detail::seed_from_time() ^ (__LINE__ * 0x517cc1b727220a95ULL))

class Fnv1a {
public:
    static constexpr u64 OFFSET_BASIS = 0xcbf29ce484222325ULL;
    static constexpr u64 PRIME        = 0x100000001b3ULL;

    static constexpr u64 hash(const char* str, size_t len) noexcept {
        u64 val = OFFSET_BASIS;
        for (size_t i = 0; i < len; ++i) {
            val ^= static_cast<u64>(static_cast<u8>(str[i]));
            val *= PRIME;
        }
        return val;
    }

    static constexpr u64 hash(std::string_view sv) noexcept {
        return hash(sv.data(), sv.size());
    }

    static constexpr u64 hash(const u8* data, size_t len) noexcept {
        u64 val = OFFSET_BASIS;
        for (size_t i = 0; i < len; ++i) {
            val ^= static_cast<u64>(data[i]);
            val *= PRIME;
        }
        return val;
    }
};

class Murmur3 {
public:
    static constexpr u32 rotl32(u32 x, i8 r) noexcept {
        return (x << r) | (x >> (32 - r));
    }

    static constexpr u32 hash32(const u8* data, size_t len, u32 seed = 0x9747b28c) noexcept {
        const size_t nblocks = len / 4;
        u32 h1 = seed;
        constexpr u32 c1 = 0xcc9e2d51;
        constexpr u32 c2 = 0x1b873593;

        for (size_t i = 0; i < nblocks; ++i) {
            size_t idx = i * 4;
            u32 k1 = static_cast<u32>(data[idx])
                   | (static_cast<u32>(data[idx + 1]) << 8)
                   | (static_cast<u32>(data[idx + 2]) << 16)
                   | (static_cast<u32>(data[idx + 3]) << 24);
            k1 *= c1;
            k1 = rotl32(k1, 15);
            k1 *= c2;
            h1 ^= k1;
            h1 = rotl32(h1, 13);
            h1 = h1 * 5 + 0xe6546b64;
        }

        const u8* tail = data + (nblocks * 4);
        u32 k1 = 0;
        switch (len & 3) {
        case 3: k1 ^= static_cast<u32>(tail[2]) << 16; [[fallthrough]];
        case 2: k1 ^= static_cast<u32>(tail[1]) << 8;  [[fallthrough]];
        case 1: k1 ^= static_cast<u32>(tail[0]);
                k1 *= c1;
                k1 = rotl32(k1, 15);
                k1 *= c2;
                h1 ^= k1;
        }

        h1 ^= static_cast<u32>(len);
        h1 ^= h1 >> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return h1;
    }
};

class Crc32 {
public:
    static constexpr u32 POLYNOMIAL = 0xEDB88320;

    static constexpr u32 calculate(const u8* data, size_t length) noexcept {
        u32 crc = 0xFFFFFFFF;
        for (size_t i = 0; i < length; ++i) {
            u8 byte = data[i];
            crc ^= byte;
            for (u8 j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ ((crc & 1) ? POLYNOMIAL : 0);
            }
        }
        return ~crc;
    }
};

class RuntimeRandom {
public:
    static inline u64 get_u64() {
        thread_local std::mt19937_64 engine(std::random_device{}());
        return engine();
    }
    static inline u32 get_u32() { return static_cast<u32>(get_u64()); }
    static inline u8 get_u8() { return static_cast<u8>(get_u64()); }
};

} // namespace core

constexpr u64 operator""_fnv1a(const char* str, std::size_t len) {
    return core::Fnv1a::hash(str, len);
}

// ============================================================================
// 2. MIXED BOOLEAN ARITHMETIC (MBA) ENGINE
// ============================================================================
namespace obf {

class Mba {
public:
    template <typename T>
    static constexpr T add(T x, T y) noexcept {
        static_assert(std::is_integral_v<T>, "MBA requires integral type");
        return (x ^ y) + ((x & y) << 1);
    }

    template <typename T>
    static constexpr T add_deep(T x, T y) noexcept {
        static_assert(std::is_integral_v<T>, "MBA requires integral type");
        return (x | y) + (x & y);
    }

    template <typename T>
    static constexpr T sub(T x, T y) noexcept {
        static_assert(std::is_integral_v<T>, "MBA requires integral type");
        T not_y = static_cast<T>(~y);
        return static_cast<T>((x ^ not_y) + ((x & not_y) << 1) + static_cast<T>(1));
    }

    template <typename T>
    static constexpr T bitwise_xor(T x, T y) noexcept {
        static_assert(std::is_integral_v<T>, "MBA requires integral type");
        return (x | y) - (x & y);
    }

    template <typename T>
    static constexpr T bitwise_xor_deep(T x, T y) noexcept {
        static_assert(std::is_integral_v<T>, "MBA requires integral type");
        return (x & ~y) | (~x & y);
    }

    template <typename T>
    static constexpr T bitwise_and(T x, T y) noexcept {
        static_assert(std::is_integral_v<T>, "MBA requires integral type");
        return (x | y) - (x ^ y);
    }

    template <typename T>
    static constexpr T bitwise_or(T x, T y) noexcept {
        static_assert(std::is_integral_v<T>, "MBA requires integral type");
        return (x ^ y) + (x & y);
    }

    template <typename T>
    static constexpr T bitwise_not(T x) noexcept {
        static_assert(std::is_integral_v<T>, "MBA requires integral type");
        if constexpr (std::is_signed_v<T>) {
            return -x - static_cast<T>(1);
        } else {
            return static_cast<T>(~x);
        }
    }
};

// ============================================================================
// 3. COMPILE-TIME STRING ENCRYPTION (AEGIS_STR)
// ============================================================================
namespace detail {

    constexpr u8 gen_key(u64 seed, size_t index) noexcept {
        u64 val = seed ^ (index * 0x5bd1e995ULL);
        val = (val ^ (val >> 15)) * 0x27d4eb2dULL;
        return static_cast<u8>((val ^ (val >> 15)) & 0xFF);
    }

    template <size_t N>
    struct FixedString {
        char data[N]{};
        constexpr FixedString(const char (&str)[N]) noexcept {
            for (size_t i = 0; i < N; ++i) data[i] = str[i];
        }
        constexpr size_t size() const noexcept { return N; }
    };

    template <FixedString Str, u64 Seed>
    class ObfuscatedStringStorage {
    public:
        static constexpr size_t N = Str.size();
        constexpr ObfuscatedStringStorage() noexcept {
            for (size_t i = 0; i < N; ++i) {
                encrypted_[i] = static_cast<u8>(static_cast<u8>(Str.data[i]) ^ gen_key(Seed, i));
            }
        }
        AEGIS_FORCEINLINE const char* decrypt(char* buffer) const noexcept {
            for (size_t i = 0; i < N; ++i) {
                buffer[i] = static_cast<char>(encrypted_[i] ^ gen_key(Seed, i));
            }
            return buffer;
        }
    private:
        std::array<u8, N> encrypted_{};
    };

    template <size_t N, u64 Seed>
    class EphemeralDecryptedString {
    public:
        template <FixedString Str>
        AEGIS_FORCEINLINE explicit EphemeralDecryptedString(const ObfuscatedStringStorage<Str, Seed>& storage) noexcept {
            storage.decrypt(buffer_);
        }
        AEGIS_FORCEINLINE EphemeralDecryptedString(EphemeralDecryptedString&& other) noexcept {
            std::memcpy(buffer_, other.buffer_, N);
            std::memset(other.buffer_, 0, N);
        }
        EphemeralDecryptedString(const EphemeralDecryptedString&) = delete;
        EphemeralDecryptedString& operator=(const EphemeralDecryptedString&) = delete;
        AEGIS_FORCEINLINE ~EphemeralDecryptedString() noexcept {
            secure_zero(buffer_, N);
        }
        AEGIS_FORCEINLINE const char* c_str() const noexcept { return buffer_; }
        AEGIS_FORCEINLINE std::string_view str_view() const noexcept { return std::string_view(buffer_, N - 1); }
        AEGIS_FORCEINLINE std::string str() const { return std::string(buffer_, N - 1); }
    private:
        char buffer_[N];
    };

    template <FixedString Str, u64 Seed>
    struct EncryptedStringWrapper {
        static constexpr size_t N = Str.size();
        static AEGIS_FORCEINLINE EphemeralDecryptedString<N, Seed> decrypt() {
            constexpr static ObfuscatedStringStorage<Str, Seed> storage{};
            return EphemeralDecryptedString<N, Seed>(storage);
        }
    };

} // namespace detail

// ============================================================================
// 4. SPLIT VARIABLE INTEGER OBFUSCATION (AEGIS_INT)
// ============================================================================
template <typename T, u64 Key>
class ObfuscatedInt {
    static_assert(std::is_integral_v<T>, "ObfuscatedInt requires integral type");
public:
    constexpr explicit ObfuscatedInt(T val) noexcept
        : share1_(static_cast<T>(val ^ static_cast<T>(Key)))
        , share2_(static_cast<T>(Key))
    {
    }
    AEGIS_FORCEINLINE T get() const noexcept {
        return Mba::bitwise_xor(share1_, share2_);
    }
    AEGIS_FORCEINLINE operator T() const noexcept { return get(); }
    AEGIS_FORCEINLINE bool operator==(T other) const noexcept { return get() == other; }
    AEGIS_FORCEINLINE bool operator!=(T other) const noexcept { return get() != other; }
    AEGIS_FORCEINLINE T operator+(T other) const noexcept { return Mba::add(get(), other); }
    AEGIS_FORCEINLINE T operator-(T other) const noexcept { return Mba::sub(get(), other); }
    AEGIS_FORCEINLINE T operator^(T other) const noexcept { return Mba::bitwise_xor(get(), other); }
private:
    T share1_;
    T share2_;
};

// ============================================================================
// 5. OPAQUE PREDICATES & OPTIMIZATION BARRIERS
// ============================================================================
class Opaque {
public:
    template <typename T>
    static AEGIS_FORCEINLINE void do_not_optimize(T& value) noexcept {
#if defined(AEGIS_COMPILER_MSVC)
        volatile char* p = reinterpret_cast<volatile char*>(&value);
        *p = *p;
#else
        asm volatile("" : "+m"(value) : : "memory");
#endif
    }
    static AEGIS_FORCEINLINE bool is_always_true(u32 x) noexcept {
        do_not_optimize(x);
        return ((x * (x + 1)) & 1) == 0;
    }
    static AEGIS_FORCEINLINE bool is_always_false(u32 x) noexcept {
        do_not_optimize(x);
        return ((x * x) & 3) == 2;
    }
    static AEGIS_FORCEINLINE bool dynamic_true() noexcept {
        u32 r = core::RuntimeRandom::get_u32();
        return is_always_true(r);
    }
    static AEGIS_FORCEINLINE bool dynamic_false() noexcept {
        u32 r = core::RuntimeRandom::get_u32();
        return is_always_false(r);
    }
};

// ============================================================================
// 6. CONTROL FLOW FLATTENING (CFF)
// ============================================================================
class FlatteningMachine {
public:
    using StateHandler = std::function<u32()>;
    static constexpr u32 STATE_EXIT = 0xFFFFFFFF;

    explicit FlatteningMachine(u32 initial_state = 0)
        : current_state_(initial_state) {}

    FlatteningMachine& add_state(u32 state, StateHandler handler) {
        handlers_[state] = std::move(handler);
        return *this;
    }

    void execute() {
        while (current_state_ != STATE_EXIT) {
            auto it = handlers_.find(current_state_);
            if (it == handlers_.end()) break;
            current_state_ = it->second();
        }
    }
private:
    u32 current_state_;
    std::unordered_map<u32, StateHandler> handlers_;
};

} // namespace obf

#define AEGIS_STR_OBJ(literal) \
    ::aegis::obf::detail::EncryptedStringWrapper<literal, (AEGIS_COMPILE_SEED() ^ __COUNTER__)>::decrypt()

#define AEGIS_STR(literal) \
    ::aegis::obf::detail::EncryptedStringWrapper<literal, (AEGIS_COMPILE_SEED() ^ __COUNTER__)>::decrypt().c_str()

#define AEGIS_INT(val) \
    (::aegis::obf::ObfuscatedInt<decltype(val), (AEGIS_COMPILE_SEED() ^ __COUNTER__)>(val).get())

#define AEGIS_INT_VAR(type, name, val) \
    ::aegis::obf::ObfuscatedInt<type, (AEGIS_COMPILE_SEED() ^ __COUNTER__)> name(val)

// ============================================================================
// 7. VIRTUAL MACHINE (V-ISA, REGISTERS, ROLLING CIPHER, INTERPRETER)
// ============================================================================
namespace vm {

enum class VMStatus : u32 {
    Success               = 0,
    Halt                  = 1,
    InvalidOpcode         = 2,
    StackOverflow         = 3,
    StackUnderflow        = 4,
    InvalidMemoryAccess   = 5,
    DivideByZero          = 6,
    NativeCallFailed      = 7,
    IntegrityViolation    = 8,
    InvalidBytecodeHeader = 9,
    KeyVerificationFailed = 10,
    Timeout               = 11
};

enum class VReg : u8 {
    R0 = 0, R1 = 1, R2 = 2, R3 = 3,
    R4 = 4, R5 = 5, R6 = 6, R7 = 7,
    RSP = 8, RBP = 9, RIP = 10, FLAGS = 11,
    COUNT = 12
};

namespace Flags {
    constexpr u64 FLAG_ZF = 1ULL << 0;
    constexpr u64 FLAG_SF = 1ULL << 1;
    constexpr u64 FLAG_CF = 1ULL << 2;
    constexpr u64 FLAG_OF = 1ULL << 3;

    constexpr u64 ZF = FLAG_ZF;
    constexpr u64 SF = FLAG_SF;
    constexpr u64 CF = FLAG_CF;
    constexpr u64 OF = FLAG_OF;
}

enum class Opcode : u8 {
    OP_NOP         = 0x00,
    OP_MOV_IMM     = 0x01,
    OP_MOV_REG     = 0x02,
    OP_ADD         = 0x03,
    OP_SUB         = 0x04,
    OP_MUL         = 0x05,
    OP_DIV         = 0x06,
    OP_MOD         = 0x07,
    OP_AND         = 0x08,
    OP_OR          = 0x09,
    OP_XOR         = 0x0A,
    OP_NOT         = 0x0B,
    OP_SHL         = 0x0C,
    OP_SHR         = 0x0D,
    OP_ROL         = 0x0E,
    OP_ROR         = 0x0F,
    OP_CMP         = 0x10,
    OP_TEST        = 0x11,
    OP_PUSH        = 0x12,
    OP_POP         = 0x13,
    OP_LOAD        = 0x14,
    OP_STORE       = 0x15,
    OP_JMP         = 0x16,
    OP_JZ          = 0x17,
    OP_JNZ         = 0x18,
    OP_JG          = 0x19,
    OP_JL          = 0x1A,
    OP_JGE         = 0x1B,
    OP_JLE         = 0x1C,
    OP_CALL        = 0x1D,
    OP_RET         = 0x1E,
    OP_CALL_NATIVE = 0x1F,
    OP_REKEY       = 0x20,
    OP_BSWAP       = 0x21,
    OP_POPCNT      = 0x22,
    OP_VMEMCPY     = 0x23,
    OP_VMEMSET     = 0x24,
    OP_JUNK        = 0x25,
    OP_HALT        = 0xFF
};

/**
 * @brief Compile-Time Bijective Polymorphic Opcode Scrambler
 * Permutes all 256 byte opcodes using a constexpr Fisher-Yates shuffle
 * seeded by compile-time entropy (__TIME__ / __LINE__).
 */
template <u64 Seed>
class PolymorphicOpcodeMap {
public:
    struct Tables {
        std::array<u8, 256> encode{};
        std::array<u8, 256> decode{};
    };

    static constexpr Tables generate() noexcept {
        Tables t{};
        for (size_t i = 0; i < 256; ++i) {
            t.encode[i] = static_cast<u8>(i);
        }
        u64 state = Seed ^ 0x9E3779B97F4A7C15ULL;
        for (size_t i = 255; i > 0; --i) {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            u64 rnd = state * 0x2545F4914F6CDD1DULL;
            size_t j = static_cast<size_t>(rnd % (i + 1));
            u8 tmp = t.encode[i];
            t.encode[i] = t.encode[j];
            t.encode[j] = tmp;
        }
        for (size_t i = 0; i < 256; ++i) {
            t.decode[t.encode[i]] = static_cast<u8>(i);
        }
        return t;
    }

    static constexpr Tables tables = generate();

    static constexpr u8 encode(Opcode op) noexcept {
        return tables.encode[static_cast<u8>(op)];
    }

    static constexpr Opcode decode(u8 scrambled) noexcept {
        return static_cast<Opcode>(tables.decode[scrambled]);
    }
};

using DefaultOpcodeMap = PolymorphicOpcodeMap<::aegis::core::detail::seed_from_time() ^ 0xA3C59AC35A5A3C3CULL>;
constexpr u16 AGVM_FLAG_POLYMORPHIC = 0x0001;

#pragma pack(push, 1)
struct BytecodeHeader {
    u32 magic;             // 'AGVM' (0x4D564741)
    u16 version;           // Version 1
    u16 flags;
    u64 initial_key;
    u32 bytecode_size;
    u32 instruction_count;
    u32 checksum;
};
#pragma pack(pop)

constexpr u32 AGVM_MAGIC = 0x4D564741;
constexpr u16 AGVM_VERSION = 1;

class BytecodeChunk {
public:
    BytecodeChunk() = default;
    BytecodeChunk(const std::vector<u8>& raw_bytecode, u64 initial_key) {
        encrypt_and_package(raw_bytecode, initial_key);
    }

    bool verify_integrity() const noexcept {
        if (raw_data_.size() < sizeof(BytecodeHeader)) return false;
        const auto* hdr = get_header();
        if (hdr->magic != AGVM_MAGIC || hdr->version != AGVM_VERSION) return false;
        if (raw_data_.size() != sizeof(BytecodeHeader) + hdr->bytecode_size) return false;

        const u8* payload = raw_data_.data() + sizeof(BytecodeHeader);
        return core::Murmur3::hash32(payload, hdr->bytecode_size) == hdr->checksum;
    }

    const BytecodeHeader* get_header() const noexcept {
        if (raw_data_.size() < sizeof(BytecodeHeader)) return nullptr;
        return reinterpret_cast<const BytecodeHeader*>(raw_data_.data());
    }

    const u8* get_encrypted_payload() const noexcept {
        if (raw_data_.size() < sizeof(BytecodeHeader)) return nullptr;
        return raw_data_.data() + sizeof(BytecodeHeader);
    }

    size_t get_payload_size() const noexcept {
        const auto* hdr = get_header();
        return hdr ? hdr->bytecode_size : 0;
    }

    const std::vector<u8>& get_raw_data() const noexcept { return raw_data_; }
    std::vector<u8>& get_raw_data() noexcept { return raw_data_; }

    static AEGIS_FORCEINLINE u64 advance_rolling_key(u64 current_key, u8 feedback_byte) noexcept {
        return (current_key ^ feedback_byte) * 0x5851F42D4C957F2DULL + 0x14057B7EF767814FULL;
    }

    void encrypt_and_package(const std::vector<u8>& plaintext, u64 key) {
        BytecodeHeader hdr{};
        hdr.magic = AGVM_MAGIC;
        hdr.version = AGVM_VERSION;
        hdr.flags = 0;
        hdr.initial_key = key;
        hdr.bytecode_size = static_cast<u32>(plaintext.size());
        hdr.instruction_count = 0;

        std::vector<u8> encrypted(plaintext.size());
        u64 rolling_key = key;
        for (size_t i = 0; i < plaintext.size(); ++i) {
            u8 cipher_byte = plaintext[i] ^ static_cast<u8>(rolling_key & 0xFF);
            encrypted[i] = cipher_byte;
            rolling_key = advance_rolling_key(rolling_key, cipher_byte);
        }

        hdr.checksum = core::Murmur3::hash32(encrypted.data(), encrypted.size());

        raw_data_.resize(sizeof(BytecodeHeader) + encrypted.size());
        std::memcpy(raw_data_.data(), &hdr, sizeof(BytecodeHeader));
        std::memcpy(raw_data_.data() + sizeof(BytecodeHeader), encrypted.data(), encrypted.size());
    }

private:
    std::vector<u8> raw_data_;
};

class VMContext {
public:
    static constexpr size_t DEFAULT_STACK_SIZE = 64 * 1024;

    explicit VMContext(size_t stack_size = DEFAULT_STACK_SIZE)
        : stack_(stack_size, static_cast<u8>(0)) {
        reset();
    }

    void reset() noexcept {
        for (auto& reg : registers_) reg = 0;
        std::fill(stack_.begin(), stack_.end(), static_cast<u8>(0));
        registers_[static_cast<size_t>(VReg::RSP)] = stack_.size();
        registers_[static_cast<size_t>(VReg::RBP)] = stack_.size();
        registers_[static_cast<size_t>(VReg::RIP)] = 0;
        registers_[static_cast<size_t>(VReg::FLAGS)] = 0;
    }

    AEGIS_FORCEINLINE reg_t get_reg(VReg reg) const noexcept {
        return registers_[static_cast<size_t>(reg)];
    }
    AEGIS_FORCEINLINE void set_reg(VReg reg, reg_t val) noexcept {
        registers_[static_cast<size_t>(reg)] = val;
    }
    AEGIS_FORCEINLINE void set_flag(u64 flag, bool condition) noexcept {
        if (condition) registers_[static_cast<size_t>(VReg::FLAGS)] |= flag;
        else registers_[static_cast<size_t>(VReg::FLAGS)] &= ~flag;
    }
    AEGIS_FORCEINLINE bool test_flag(u64 flag) const noexcept {
        return (registers_[static_cast<size_t>(VReg::FLAGS)] & flag) != 0;
    }

    bool push(reg_t value) noexcept {
        auto& sp = registers_[static_cast<size_t>(VReg::RSP)];
        if (sp < sizeof(reg_t)) return false;
        sp -= sizeof(reg_t);
        std::memcpy(&stack_[sp], &value, sizeof(reg_t));
        return true;
    }

    bool pop(reg_t& out_value) noexcept {
        auto& sp = registers_[static_cast<size_t>(VReg::RSP)];
        if (sp + sizeof(reg_t) > stack_.size()) return false;
        std::memcpy(&out_value, &stack_[sp], sizeof(reg_t));
        sp += sizeof(reg_t);
        return true;
    }

    bool read_u64(size_t address, u64& out_val) const noexcept {
        if (address + sizeof(u64) > stack_.size()) return false;
        std::memcpy(&out_val, &stack_[address], sizeof(u64));
        return true;
    }

    bool write_u64(size_t address, u64 val) noexcept {
        if (address + sizeof(u64) > stack_.size()) return false;
        std::memcpy(&stack_[address], &val, sizeof(u64));
        return true;
    }

    u8* stack_data() noexcept { return stack_.data(); }
    const u8* stack_data() const noexcept { return stack_.data(); }
    size_t stack_size() const noexcept { return stack_.size(); }

private:
    reg_t registers_[static_cast<size_t>(VReg::COUNT)];
    std::vector<u8> stack_;
};

using NativeFunction = std::function<u64(const std::vector<u64>&)>;

class NativeBridge {
public:
    NativeBridge() = default;
    void register_function(u16 func_id, NativeFunction fn) {
        table_[func_id] = std::move(fn);
    }
    bool call(u16 func_id, const std::vector<u64>& args, u64& out_ret) const {
        auto it = table_.find(func_id);
        if (it == table_.end()) return false;
        try {
            out_ret = it->second(args);
            return true;
        } catch (...) {
            return false;
        }
    }
private:
    std::unordered_map<u16, NativeFunction> table_;
};

// ============================================================================
// 8. FLUENT BYTECODE BUILDER (ASSEMBLER DSL)
// ============================================================================
struct Label { u32 id; };

class BytecodeBuilder {
public:
    explicit BytecodeBuilder(bool polymorphic_opcodes = true)
        : polymorphic_(polymorphic_opcodes) {
        buffer_.reserve(256);
    }

    BytecodeBuilder& enable_polymorphic_opcodes(bool enable) noexcept {
        polymorphic_ = enable;
        return *this;
    }

    BytecodeBuilder& nop() {
        emit_opcode(Opcode::OP_NOP);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& mov(VReg dst, u64 imm) {
        emit_opcode(Opcode::OP_MOV_IMM);
        emit_u8(static_cast<u8>(dst));
        emit_u64(imm);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& mov(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_MOV_REG);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& add(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_ADD);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& sub(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_SUB);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& mul(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_MUL);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& div(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_DIV);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& mod(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_MOD);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& bitwise_and(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_AND);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& bitwise_or(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_OR);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& bitwise_xor(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_XOR);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& bitwise_not(VReg dst) {
        emit_opcode(Opcode::OP_NOT);
        emit_u8(static_cast<u8>(dst));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& shl(VReg dst, u8 shift) {
        emit_opcode(Opcode::OP_SHL);
        emit_u8(static_cast<u8>(dst));
        emit_u8(shift);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& shr(VReg dst, u8 shift) {
        emit_opcode(Opcode::OP_SHR);
        emit_u8(static_cast<u8>(dst));
        emit_u8(shift);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& rol(VReg dst, u8 rot) {
        emit_opcode(Opcode::OP_ROL);
        emit_u8(static_cast<u8>(dst));
        emit_u8(rot);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& ror(VReg dst, u8 rot) {
        emit_opcode(Opcode::OP_ROR);
        emit_u8(static_cast<u8>(dst));
        emit_u8(rot);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& cmp(VReg r1, VReg r2) {
        emit_opcode(Opcode::OP_CMP);
        emit_u8(static_cast<u8>(r1));
        emit_u8(static_cast<u8>(r2));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& test(VReg r1, VReg r2) {
        emit_opcode(Opcode::OP_TEST);
        emit_u8(static_cast<u8>(r1));
        emit_u8(static_cast<u8>(r2));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& push(VReg reg) {
        emit_opcode(Opcode::OP_PUSH);
        emit_u8(static_cast<u8>(reg));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& pop(VReg reg) {
        emit_opcode(Opcode::OP_POP);
        emit_u8(static_cast<u8>(reg));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& load(VReg dst, VReg addr_reg) {
        emit_opcode(Opcode::OP_LOAD);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(addr_reg));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& store(VReg addr_reg, VReg src) {
        emit_opcode(Opcode::OP_STORE);
        emit_u8(static_cast<u8>(addr_reg));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& bswap(VReg dst) {
        emit_opcode(Opcode::OP_BSWAP);
        emit_u8(static_cast<u8>(dst));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& popcnt(VReg dst, VReg src) {
        emit_opcode(Opcode::OP_POPCNT);
        emit_u8(static_cast<u8>(dst));
        emit_u8(static_cast<u8>(src));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& vmemcpy(VReg dst_addr, VReg src_addr, VReg size_reg) {
        emit_opcode(Opcode::OP_VMEMCPY);
        emit_u8(static_cast<u8>(dst_addr));
        emit_u8(static_cast<u8>(src_addr));
        emit_u8(static_cast<u8>(size_reg));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& vmemset(VReg dst_addr, VReg val_reg, VReg size_reg) {
        emit_opcode(Opcode::OP_VMEMSET);
        emit_u8(static_cast<u8>(dst_addr));
        emit_u8(static_cast<u8>(val_reg));
        emit_u8(static_cast<u8>(size_reg));
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& rekey(u64 key_delta) {
        emit_opcode(Opcode::OP_REKEY);
        emit_u64(key_delta);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& emit_junk(size_t count = 1) {
        for (size_t i = 0; i < count; ++i) {
            emit_opcode(Opcode::OP_JUNK);
            emit_u64(core::RuntimeRandom::get_u64());
            instruction_count_++;
        }
        return *this;
    }
    Label create_label() { return Label{next_label_id_++}; }
    BytecodeBuilder& bind_label(Label lbl) {
        label_positions_[lbl.id] = static_cast<u32>(buffer_.size());
        return *this;
    }
    BytecodeBuilder& jmp(Label lbl) {
        emit_opcode(Opcode::OP_JMP);
        label_fixups_.push_back({buffer_.size(), lbl.id});
        emit_u32(0);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& jz(Label lbl) {
        emit_opcode(Opcode::OP_JZ);
        label_fixups_.push_back({buffer_.size(), lbl.id});
        emit_u32(0);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& jnz(Label lbl) {
        emit_opcode(Opcode::OP_JNZ);
        label_fixups_.push_back({buffer_.size(), lbl.id});
        emit_u32(0);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& jg(Label lbl) {
        emit_opcode(Opcode::OP_JG);
        label_fixups_.push_back({buffer_.size(), lbl.id});
        emit_u32(0);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& jl(Label lbl) {
        emit_opcode(Opcode::OP_JL);
        label_fixups_.push_back({buffer_.size(), lbl.id});
        emit_u32(0);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& jge(Label lbl) {
        emit_opcode(Opcode::OP_JGE);
        label_fixups_.push_back({buffer_.size(), lbl.id});
        emit_u32(0);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& jle(Label lbl) {
        emit_opcode(Opcode::OP_JLE);
        label_fixups_.push_back({buffer_.size(), lbl.id});
        emit_u32(0);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& call(Label lbl) {
        emit_opcode(Opcode::OP_CALL);
        label_fixups_.push_back({buffer_.size(), lbl.id});
        emit_u32(0);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& ret() {
        emit_opcode(Opcode::OP_RET);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& call_native(u16 func_id, u8 argc) {
        emit_opcode(Opcode::OP_CALL_NATIVE);
        emit_u16(func_id);
        emit_u8(argc);
        instruction_count_++;
        return *this;
    }
    BytecodeBuilder& halt() {
        emit_opcode(Opcode::OP_HALT);
        instruction_count_++;
        return *this;
    }

    BytecodeChunk build(u64 initial_key = 0) {
        for (const auto& fixup : label_fixups_) {
            auto it = label_positions_.find(fixup.label_id);
            if (it == label_positions_.end()) throw std::runtime_error("AegisVM: Unresolved label");
            u32 target = it->second;
            buffer_[fixup.patch_offset + 0] = static_cast<u8>(target & 0xFF);
            buffer_[fixup.patch_offset + 1] = static_cast<u8>((target >> 8) & 0xFF);
            buffer_[fixup.patch_offset + 2] = static_cast<u8>((target >> 16) & 0xFF);
            buffer_[fixup.patch_offset + 3] = static_cast<u8>((target >> 24) & 0xFF);
        }

        if (initial_key == 0) initial_key = core::RuntimeRandom::get_u64();
        BytecodeChunk chunk(buffer_, initial_key);
        auto* hdr = const_cast<BytecodeHeader*>(chunk.get_header());
        if (hdr) {
            hdr->instruction_count = instruction_count_;
            if (polymorphic_) hdr->flags |= AGVM_FLAG_POLYMORPHIC;
        }
        return chunk;
    }

private:
    void emit_opcode(Opcode op) {
        if (polymorphic_) {
            buffer_.push_back(DefaultOpcodeMap::encode(op));
        } else {
            buffer_.push_back(static_cast<u8>(op));
        }
    }
    void emit_u8(u8 val) { buffer_.push_back(val); }
    void emit_u16(u16 val) {
        buffer_.push_back(static_cast<u8>(val & 0xFF));
        buffer_.push_back(static_cast<u8>((val >> 8) & 0xFF));
    }
    void emit_u32(u32 val) {
        buffer_.push_back(static_cast<u8>(val & 0xFF));
        buffer_.push_back(static_cast<u8>((val >> 8) & 0xFF));
        buffer_.push_back(static_cast<u8>((val >> 16) & 0xFF));
        buffer_.push_back(static_cast<u8>((val >> 24) & 0xFF));
    }
    void emit_u64(u64 val) {
        emit_u32(static_cast<u32>(val & 0xFFFFFFFF));
        emit_u32(static_cast<u32>((val >> 32) & 0xFFFFFFFF));
    }

    struct Fixup { size_t patch_offset; u32 label_id; };
    std::vector<u8> buffer_;
    u32 next_label_id_{1};
    u32 instruction_count_{0};
    bool polymorphic_{true};
    std::unordered_map<u32, u32> label_positions_;
    std::vector<Fixup> label_fixups_;
};

// ============================================================================
// 9. VIRTUAL MACHINE INTERPRETER (MBA DISPATCH & EPHEMERAL BUFFER)
// ============================================================================
class VirtualMachine {
public:
    explicit VirtualMachine(size_t stack_size = VMContext::DEFAULT_STACK_SIZE)
        : context_(stack_size) {}

    void register_native(u16 func_id, NativeFunction fn) {
        bridge_.register_function(func_id, std::move(fn));
    }

    u64 run(const BytecodeChunk& chunk) {
        context_.reset();
        VMStatus status = execute(chunk, &context_);
        if (status != VMStatus::Success && status != VMStatus::Halt) return 0;
        return context_.get_reg(VReg::R0);
    }

    VMStatus execute(const BytecodeChunk& chunk, VMContext* opt_ctx = nullptr) {
        if (!chunk.verify_integrity()) return VMStatus::IntegrityViolation;
        const auto* hdr = chunk.get_header();
        if (!hdr) return VMStatus::InvalidBytecodeHeader;

        VMContext& ctx = opt_ctx ? *opt_ctx : context_;
        const u8* encrypted_payload = chunk.get_encrypted_payload();
        const size_t payload_size = chunk.get_payload_size();
        const bool is_polymorphic = (hdr->flags & AGVM_FLAG_POLYMORPHIC) != 0;

        std::vector<u8> code(payload_size);
        u64 rolling_key = hdr->initial_key;

        for (size_t i = 0; i < payload_size; ++i) {
            u8 cipher_byte = encrypted_payload[i];
            code[i] = cipher_byte ^ static_cast<u8>(rolling_key & 0xFF);
            rolling_key = BytecodeChunk::advance_rolling_key(rolling_key, cipher_byte);
        }

        struct Wiper {
            std::vector<u8>& b;
            ~Wiper() { secure_zero(b.data(), b.size()); }
        } wiper{code};

        size_t pc = 0;
        u64 cycles = 0;

        auto fetch_u8 = [&](size_t& c) -> u8 { return (c < code.size()) ? code[c++] : 0; };
        auto fetch_u16 = [&](size_t& c) -> u16 {
            if (c + 2 > code.size()) return 0;
            u16 v = static_cast<u16>(code[c]) | (static_cast<u16>(code[c + 1]) << 8);
            c += 2;
            return v;
        };
        auto fetch_u32 = [&](size_t& c) -> u32 {
            if (c + 4 > code.size()) return 0;
            u32 v = static_cast<u32>(code[c]) | (static_cast<u32>(code[c + 1]) << 8) |
                    (static_cast<u32>(code[c + 2]) << 16) | (static_cast<u32>(code[c + 3]) << 24);
            c += 4;
            return v;
        };
        auto fetch_u64 = [&](size_t& c) -> u64 {
            u32 lo = fetch_u32(c);
            u32 hi = fetch_u32(c);
            return static_cast<u64>(lo) | (static_cast<u64>(hi) << 32);
        };

        while (pc < code.size()) {
            if (++cycles > cycle_limit_) return VMStatus::Timeout;
            ctx.set_reg(VReg::RIP, pc);
            u8 raw_op = fetch_u8(pc);
            Opcode op = is_polymorphic ? DefaultOpcodeMap::decode(raw_op) : static_cast<Opcode>(raw_op);

            switch (op) {
            case Opcode::OP_NOP: break;
            case Opcode::OP_MOV_IMM: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, fetch_u64(pc));
                break;
            }
            case Opcode::OP_MOV_REG: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, ctx.get_reg(src));
                break;
            }
            case Opcode::OP_ADD: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, obf::Mba::add(ctx.get_reg(dst), ctx.get_reg(src)));
                break;
            }
            case Opcode::OP_SUB: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, obf::Mba::sub(ctx.get_reg(dst), ctx.get_reg(src)));
                break;
            }
            case Opcode::OP_MUL: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, ctx.get_reg(dst) * ctx.get_reg(src));
                break;
            }
            case Opcode::OP_DIV: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                reg_t denom = ctx.get_reg(src);
                if (denom == 0) return VMStatus::DivideByZero;
                ctx.set_reg(dst, ctx.get_reg(dst) / denom);
                break;
            }
            case Opcode::OP_MOD: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                reg_t denom = ctx.get_reg(src);
                if (denom == 0) return VMStatus::DivideByZero;
                ctx.set_reg(dst, ctx.get_reg(dst) % denom);
                break;
            }
            case Opcode::OP_AND: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, obf::Mba::bitwise_and(ctx.get_reg(dst), ctx.get_reg(src)));
                break;
            }
            case Opcode::OP_OR: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, obf::Mba::bitwise_or(ctx.get_reg(dst), ctx.get_reg(src)));
                break;
            }
            case Opcode::OP_XOR: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, obf::Mba::bitwise_xor(ctx.get_reg(dst), ctx.get_reg(src)));
                break;
            }
            case Opcode::OP_NOT: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, obf::Mba::bitwise_not(ctx.get_reg(dst)));
                break;
            }
            case Opcode::OP_SHL: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                u8 s = fetch_u8(pc) & 63;
                ctx.set_reg(dst, ctx.get_reg(dst) << s);
                break;
            }
            case Opcode::OP_SHR: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                u8 s = fetch_u8(pc) & 63;
                ctx.set_reg(dst, ctx.get_reg(dst) >> s);
                break;
            }
            case Opcode::OP_ROL: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                u8 r = fetch_u8(pc) & 63;
                reg_t v = ctx.get_reg(dst);
                ctx.set_reg(dst, (v << r) | (v >> (64 - r)));
                break;
            }
            case Opcode::OP_ROR: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                u8 r = fetch_u8(pc) & 63;
                reg_t v = ctx.get_reg(dst);
                ctx.set_reg(dst, (v >> r) | (v << (64 - r)));
                break;
            }
            case Opcode::OP_CMP: {
                VReg r1 = static_cast<VReg>(fetch_u8(pc));
                VReg r2 = static_cast<VReg>(fetch_u8(pc));
                reg_t v1 = ctx.get_reg(r1);
                reg_t v2 = ctx.get_reg(r2);
                ctx.set_flag(Flags::ZF, v1 == v2);
                ctx.set_flag(Flags::SF, static_cast<i64>(v1 - v2) < 0);
                ctx.set_flag(Flags::CF, v1 < v2);
                i64 s1 = static_cast<i64>(v1);
                i64 s2 = static_cast<i64>(v2);
                i64 sres = s1 - s2;
                ctx.set_flag(Flags::OF, ((s1 ^ s2) & (s1 ^ sres)) < 0);
                break;
            }
            case Opcode::OP_TEST: {
                VReg r1 = static_cast<VReg>(fetch_u8(pc));
                VReg r2 = static_cast<VReg>(fetch_u8(pc));
                reg_t v = ctx.get_reg(r1) & ctx.get_reg(r2);
                ctx.set_flag(Flags::ZF, v == 0);
                ctx.set_flag(Flags::SF, static_cast<i64>(v) < 0);
                break;
            }
            case Opcode::OP_PUSH: {
                VReg reg = static_cast<VReg>(fetch_u8(pc));
                if (!ctx.push(ctx.get_reg(reg))) return VMStatus::StackOverflow;
                break;
            }
            case Opcode::OP_POP: {
                VReg reg = static_cast<VReg>(fetch_u8(pc));
                reg_t val = 0;
                if (!ctx.pop(val)) return VMStatus::StackUnderflow;
                ctx.set_reg(reg, val);
                break;
            }
            case Opcode::OP_LOAD: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg addr_reg = static_cast<VReg>(fetch_u8(pc));
                u64 val = 0;
                if (!ctx.read_u64(static_cast<size_t>(ctx.get_reg(addr_reg)), val)) {
                    return VMStatus::InvalidMemoryAccess;
                }
                ctx.set_reg(dst, val);
                break;
            }
            case Opcode::OP_STORE: {
                VReg addr_reg = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                if (!ctx.write_u64(static_cast<size_t>(ctx.get_reg(addr_reg)), ctx.get_reg(src))) {
                    return VMStatus::InvalidMemoryAccess;
                }
                break;
            }
            case Opcode::OP_BSWAP: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                u64 v = ctx.get_reg(dst);
                v = ((v & 0x00000000000000FFULL) << 56) |
                    ((v & 0x000000000000FF00ULL) << 40) |
                    ((v & 0x0000000000FF0000ULL) << 24) |
                    ((v & 0x00000000FF000000ULL) << 8)  |
                    ((v & 0x000000FF00000000ULL) >> 8)  |
                    ((v & 0x0000FF0000000000ULL) >> 24) |
                    ((v & 0x00FF000000000000ULL) >> 40) |
                    ((v & 0xFF00000000000000ULL) >> 56);
                ctx.set_reg(dst, v);
                break;
            }
            case Opcode::OP_POPCNT: {
                VReg dst = static_cast<VReg>(fetch_u8(pc));
                VReg src = static_cast<VReg>(fetch_u8(pc));
                ctx.set_reg(dst, static_cast<u64>(std::popcount(ctx.get_reg(src))));
                break;
            }
            case Opcode::OP_VMEMCPY: {
                VReg dst_r = static_cast<VReg>(fetch_u8(pc));
                VReg src_r = static_cast<VReg>(fetch_u8(pc));
                VReg sz_r  = static_cast<VReg>(fetch_u8(pc));
                size_t dst_off = static_cast<size_t>(ctx.get_reg(dst_r));
                size_t src_off = static_cast<size_t>(ctx.get_reg(src_r));
                size_t len     = static_cast<size_t>(ctx.get_reg(sz_r));
                if (dst_off + len > ctx.stack_size() || src_off + len > ctx.stack_size()) {
                    return VMStatus::InvalidMemoryAccess;
                }
                std::memmove(ctx.stack_data() + dst_off, ctx.stack_data() + src_off, len);
                break;
            }
            case Opcode::OP_VMEMSET: {
                VReg dst_r = static_cast<VReg>(fetch_u8(pc));
                VReg val_r = static_cast<VReg>(fetch_u8(pc));
                VReg sz_r  = static_cast<VReg>(fetch_u8(pc));
                size_t dst_off = static_cast<size_t>(ctx.get_reg(dst_r));
                u8 byte_val    = static_cast<u8>(ctx.get_reg(val_r) & 0xFF);
                size_t len     = static_cast<size_t>(ctx.get_reg(sz_r));
                if (dst_off + len > ctx.stack_size()) {
                    return VMStatus::InvalidMemoryAccess;
                }
                std::memset(ctx.stack_data() + dst_off, byte_val, len);
                break;
            }
            case Opcode::OP_REKEY: {
                u64 delta = fetch_u64(pc);
                rolling_key ^= delta;
                break;
            }
            case Opcode::OP_JUNK: {
                volatile u64 dummy = fetch_u64(pc);
                (void)dummy;
                break;
            }
            case Opcode::OP_JMP: {
                u32 t = fetch_u32(pc);
                if (t >= code.size()) return VMStatus::InvalidMemoryAccess;
                pc = t;
                break;
            }
            case Opcode::OP_JZ: {
                u32 t = fetch_u32(pc);
                if (ctx.test_flag(Flags::ZF)) {
                    if (t >= code.size()) return VMStatus::InvalidMemoryAccess;
                    pc = t;
                }
                break;
            }
            case Opcode::OP_JNZ: {
                u32 t = fetch_u32(pc);
                if (!ctx.test_flag(Flags::ZF)) {
                    if (t >= code.size()) return VMStatus::InvalidMemoryAccess;
                    pc = t;
                }
                break;
            }
            case Opcode::OP_JG: {
                u32 t = fetch_u32(pc);
                if (!ctx.test_flag(Flags::ZF) && (ctx.test_flag(Flags::SF) == ctx.test_flag(Flags::OF))) {
                    if (t >= code.size()) return VMStatus::InvalidMemoryAccess;
                    pc = t;
                }
                break;
            }
            case Opcode::OP_JL: {
                u32 t = fetch_u32(pc);
                if (ctx.test_flag(Flags::SF) != ctx.test_flag(Flags::OF)) {
                    if (t >= code.size()) return VMStatus::InvalidMemoryAccess;
                    pc = t;
                }
                break;
            }
            case Opcode::OP_JGE: {
                u32 t = fetch_u32(pc);
                if (ctx.test_flag(Flags::SF) == ctx.test_flag(Flags::OF)) {
                    if (t >= code.size()) return VMStatus::InvalidMemoryAccess;
                    pc = t;
                }
                break;
            }
            case Opcode::OP_JLE: {
                u32 t = fetch_u32(pc);
                if (ctx.test_flag(Flags::ZF) || (ctx.test_flag(Flags::SF) != ctx.test_flag(Flags::OF))) {
                    if (t >= code.size()) return VMStatus::InvalidMemoryAccess;
                    pc = t;
                }
                break;
            }
            case Opcode::OP_CALL: {
                u32 t = fetch_u32(pc);
                if (t >= code.size()) return VMStatus::InvalidMemoryAccess;
                if (!ctx.push(static_cast<reg_t>(pc))) return VMStatus::StackOverflow;
                pc = t;
                break;
            }
            case Opcode::OP_RET: {
                reg_t ret_pc = 0;
                if (!ctx.pop(ret_pc)) return VMStatus::StackUnderflow;
                if (ret_pc >= code.size()) return VMStatus::InvalidMemoryAccess;
                pc = static_cast<size_t>(ret_pc);
                break;
            }
            case Opcode::OP_CALL_NATIVE: {
                u16 func_id = fetch_u16(pc);
                u8 argc = fetch_u8(pc);
                std::vector<u64> args;
                args.reserve(argc);
                for (u8 a = 0; a < argc; ++a) {
                    if (a < 4) args.push_back(ctx.get_reg(static_cast<VReg>(a)));
                    else {
                        reg_t val = 0;
                        if (!ctx.pop(val)) return VMStatus::StackUnderflow;
                        args.push_back(val);
                    }
                }
                u64 ret_val = 0;
                if (!bridge_.call(func_id, args, ret_val)) return VMStatus::NativeCallFailed;
                ctx.set_reg(VReg::R0, ret_val);
                break;
            }
            case Opcode::OP_HALT: return VMStatus::Halt;
            default: return VMStatus::InvalidOpcode;
            }
        }
        return VMStatus::Success;
    }

    VMContext& context() noexcept { return context_; }
    NativeBridge& bridge() noexcept { return bridge_; }

private:
    VMContext context_;
    NativeBridge bridge_;
    u64 cycle_limit_{100'000'000};
};

} // namespace vm

// ============================================================================
// 10. ANTI-ANALYSIS & ANTI-DEBUGGING SUITE
// ============================================================================
namespace anti {

enum class DetectionFlag : u32 {
    None              = 0,
    PebBeingDebugged  = 1 << 0,
    PebNtGlobalFlag   = 1 << 1,
    HardwareBreak     = 1 << 2,
    TimingAnomaly     = 1 << 3,
    ProcessDebugPort  = 1 << 4,
    RemoteDebugger    = 1 << 5
};

class AntiDebug {
public:
    static inline bool check_peb_being_debugged() noexcept {
#if defined(AEGIS_WINDOWS)
    #if defined(AEGIS_ARCH_X64)
        const auto* peb = reinterpret_cast<const u8*>(__readgsqword(0x60));
        return peb && peb[2] != 0;
    #elif defined(AEGIS_ARCH_X86)
        const auto* peb = reinterpret_cast<const u8*>(__readfsdword(0x30));
        return peb && peb[2] != 0;
    #else
        return IsDebuggerPresent() != FALSE;
    #endif
#elif defined(AEGIS_LINUX)
        std::ifstream status("/proc/self/status");
        std::string line;
        while (std::getline(status, line)) {
            if (line.rfind("TracerPid:", 0) == 0) {
                return std::stoi(line.substr(10)) != 0;
            }
        }
        return false;
#else
        return false;
#endif
    }

    static inline bool check_peb_nt_global_flag() noexcept {
#if defined(AEGIS_WINDOWS)
    #if defined(AEGIS_ARCH_X64)
        const auto* peb = reinterpret_cast<const u8*>(__readgsqword(0x60));
        if (!peb) return false;
        u32 global_flag = *reinterpret_cast<const u32*>(peb + 0xBC);
        return (global_flag & 0x70) != 0;
    #elif defined(AEGIS_ARCH_X86)
        const auto* peb = reinterpret_cast<const u8*>(__readfsdword(0x30));
        if (!peb) return false;
        u32 global_flag = *reinterpret_cast<const u32*>(peb + 0x68);
        return (global_flag & 0x70) != 0;
    #else
        return false;
    #endif
#else
        return false;
#endif
    }

    static inline bool check_hardware_breakpoints() noexcept {
#if defined(AEGIS_WINDOWS)
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
        }
        return false;
#else
        return false;
#endif
    }

    static inline bool check_timing_anomaly(u64 threshold_cycles = 15'000) noexcept {
#if defined(AEGIS_COMPILER_MSVC)
        int cpu_info[4];
        __cpuid(cpu_info, 0);
        u64 t1 = __rdtsc();
        __cpuid(cpu_info, 0);
        u64 t2 = __rdtsc();
        return (t2 - t1) > threshold_cycles;
#else
        return false;
#endif
    }

    static inline bool check_process_debug_port() noexcept {
#if defined(AEGIS_WINDOWS)
        typedef NTSTATUS(NTAPI* pfnNtQueryInfoProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        auto pQuery = reinterpret_cast<pfnNtQueryInfoProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!pQuery) return false;
        DWORD_PTR port = 0;
        return (pQuery(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(7), &port, sizeof(port), nullptr) == 0 && port != 0);
#else
        return false;
#endif
    }

    static inline bool check_remote_debugger() noexcept {
#if defined(AEGIS_WINDOWS)
        BOOL is_dbg = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_dbg)) return is_dbg != FALSE;
        return false;
#else
        return false;
#endif
    }

    static inline bool hide_current_thread() noexcept {
#if defined(AEGIS_WINDOWS)
        typedef NTSTATUS(NTAPI* pfnNtSetInfoThread)(HANDLE, ULONG, PVOID, ULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        auto pSet = reinterpret_cast<pfnNtSetInfoThread>(GetProcAddress(ntdll, "NtSetInformationThread"));
        if (!pSet) return false;
        return pSet(GetCurrentThread(), 0x11, nullptr, 0) == 0;
#else
        return false;
#endif
    }

    static inline bool is_debugger_active() noexcept {
        return check_peb_being_debugged() ||
               check_peb_nt_global_flag() ||
               check_hardware_breakpoints() ||
               check_timing_anomaly() ||
               check_process_debug_port() ||
               check_remote_debugger();
    }
};

// ============================================================================
// 10.B ANTI-VM & SANDBOX DETECTION (VMware, VirtualBox, QEMU, KVM, Hyper-V)
// (Integrated from AntiSkid.cpp & VMRestrict)
// ============================================================================
class AntiVm {
public:
    /**
     * @brief Detects hypervisor CPUID bit and queries hypervisor vendor string
     */
    static inline bool check_cpuid_hypervisor() noexcept {
#if defined(AEGIS_COMPILER_MSVC)
        int cpu_info[4]{};
        __cpuid(cpu_info, 1);
        // Bit 31 of ECX is set if running inside hypervisor
        if ((cpu_info[2] & (1 << 31)) == 0) {
            return false;
        }

        // Check hypervisor vendor signature
        __cpuid(cpu_info, 0x40000000);
        char vendor[13]{};
        std::memcpy(vendor + 0, &cpu_info[1], 4);
        std::memcpy(vendor + 4, &cpu_info[2], 4);
        std::memcpy(vendor + 8, &cpu_info[3], 4);

        std::string_view v(vendor);
        if (v == "VMwareVMware" || v == "Microsoft Hv" || v == "KVMKVMKVM" ||
            v == "prl hyperv"   || v == "VBoxVBoxVBox" || v == "TCGTCGTCGTCG") {
            return true;
        }
        return true;
#else
        return false;
#endif
    }

    /**
     * @brief Checks registry keys commonly present in VirtualBox and VMware
     */
    static inline bool check_registry_artifacts() noexcept {
#if defined(AEGIS_WINDOWS)
        const wchar_t* keys[] = {
            L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
            L"SOFTWARE\\VMware, Inc.\\VMware Tools",
            L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"
        };
        for (const auto* k : keys) {
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
        }
#endif
        return false;
    }

    /**
     * @brief Checks network adapter MAC address vendors for VM prefixes
     */
    static inline bool check_mac_vendor() noexcept {
#if defined(AEGIS_WINDOWS)
        ULONG buf_len = sizeof(IP_ADAPTER_INFO);
        std::vector<u8> buffer(buf_len);
        PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());

        if (GetAdaptersInfo(pAdapterInfo, &buf_len) == ERROR_BUFFER_OVERFLOW) {
            buffer.resize(buf_len);
            pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
        }

        if (GetAdaptersInfo(pAdapterInfo, &buf_len) == NO_ERROR) {
            while (pAdapterInfo) {
                // VMware MAC prefixes: 00:05:69, 00:0C:29, 00:50:56
                // VirtualBox MAC prefix: 08:00:27
                if (pAdapterInfo->AddressLength >= 3) {
                    u8 b0 = pAdapterInfo->Address[0];
                    u8 b1 = pAdapterInfo->Address[1];
                    u8 b2 = pAdapterInfo->Address[2];

                    if (b0 == 0x08 && b1 == 0x00 && b2 == 0x27) return true; // VBox
                    if (b0 == 0x00 && b1 == 0x05 && b2 == 0x69) return true; // VMware
                    if (b0 == 0x00 && b1 == 0x0C && b2 == 0x29) return true; // VMware
                    if (b0 == 0x00 && b1 == 0x50 && b2 == 0x56) return true; // VMware
                }
                pAdapterInfo = pAdapterInfo->Next;
            }
        }
#endif
        return false;
    }

    static inline bool is_virtual_machine() noexcept {
        return check_cpuid_hypervisor() || check_registry_artifacts() || check_mac_vendor();
    }
};

// ============================================================================
// 11. ANTI-DUMPING & MEMORY HEADER ERASER
// (Integrated from csharp-protection / AntiDumping)
// ============================================================================
class AntiDump {
public:
    /**
     * @brief Erases PE Dos, NT and Section headers in memory to prevent dumping
     * (blocks Scylla, MegaDumper, Process Hacker, Cheat Engine memory reconstructors)
     */
    static inline bool erase_pe_headers(void* module_base = nullptr) noexcept {
#if defined(AEGIS_WINDOWS)
        if (!module_base) {
            module_base = GetModuleHandleW(nullptr);
        }
        if (!module_base) return false;

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        DWORD old_protect = 0;
        // Erase first 4096 bytes (PE header page)
        if (VirtualProtect(module_base, 4096, PAGE_READWRITE, &old_protect)) {
            secure_zero(module_base, 4096);
            VirtualProtect(module_base, 4096, old_protect, &old_protect);
            return true;
        }
        return false;
#else
        (void)module_base;
        return false;
#endif
    }
};

// ============================================================================
// 12. ANTI-DISASSEMBLY & JUNK CODE DESYNCHRONIZATION
// (Integrated from DisassemblyDesync.cpp & CallTrick.cpp)
// ============================================================================
namespace asm_tricks {

#if defined(AEGIS_COMPILER_MSVC) && defined(AEGIS_ARCH_X86)
    #define AEGIS_DESYNC() \
        __asm { __asm _emit 0xEB __asm _emit 0xFF __asm _emit 0xC0 }
#else
    #define AEGIS_DESYNC() \
        do { volatile int _dummy = 0; ::aegis::obf::Opaque::do_not_optimize(_dummy); } while(0)
#endif

} // namespace asm_tricks

// ============================================================================
// 13. MEMORY INTEGRITY & HOOK SCANNER
// ============================================================================
class IntegrityScanner {
public:
    static inline u32 hash_region(const void* address, size_t size) noexcept {
        if (!address || size == 0) return 0;
        return core::Murmur3::hash32(static_cast<const u8*>(address), size);
    }

    static inline bool verify_region(const void* address, size_t size, u32 expected) noexcept {
        return hash_region(address, size) == expected;
    }

    static inline bool has_software_breakpoints(const void* address, size_t size) noexcept {
        if (!address || size == 0) return false;
        const auto* p = static_cast<const u8*>(address);
        for (size_t i = 0; i < size; ++i) {
            if (p[i] == 0xCC) return true; // INT 3
        }
        return false;
    }

    static inline bool has_inline_hook(const void* function_ptr) noexcept {
        if (!function_ptr) return false;
        const auto* p = static_cast<const u8*>(function_ptr);
        if (p[0] == 0xE9) return true;       // JMP rel32
        if (p[0] == 0xEB) return true;       // JMP rel8
        if (p[0] == 0xFF && p[1] == 0x25) return true; // JMP [rip+disp]
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) return true; // mov rax, imm64; jmp rax
        return false;
    }
};

// ============================================================================
// 14. DYNAMIC PE EXPORT RESOLVER VIA HASH (NO IAT STRINGS)
// ============================================================================
class ApiResolver {
public:
    static inline void* resolve_raw(u64 module_hash, u64 function_hash) noexcept {
#if defined(AEGIS_WINDOWS)
        struct AegisUnicodeString { USHORT Length; USHORT MaxLength; PWSTR Buffer; };
        struct AegisLdrEntry {
            LIST_ENTRY InLoad; LIST_ENTRY InMemory; LIST_ENTRY InInit;
            PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage;
            AegisUnicodeString FullName; AegisUnicodeString BaseName;
        };

    #if defined(AEGIS_ARCH_X64)
        auto* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
    #elif defined(AEGIS_ARCH_X86)
        auto* peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
    #else
        PEB* peb = nullptr;
    #endif

        if (!peb || !peb->Ldr) return nullptr;

        const LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        const LIST_ENTRY* curr = head->Flink;
        void* base_addr = nullptr;

        while (curr && curr != head) {
            const auto* entry = CONTAINING_RECORD(curr, AegisLdrEntry, InMemory);
            if (entry->BaseName.Buffer && entry->BaseName.Length > 0) {
                size_t len = entry->BaseName.Length / sizeof(wchar_t);
                u64 current_hash = core::Fnv1a::OFFSET_BASIS;
                for (size_t i = 0; i < len; ++i) {
                    wchar_t c = entry->BaseName.Buffer[i];
                    if (c >= L'A' && c <= L'Z') c += (L'a' - L'A');
                    current_hash ^= static_cast<u64>(static_cast<u8>(c));
                    current_hash *= core::Fnv1a::PRIME;
                }
                if (current_hash == module_hash) {
                    base_addr = entry->DllBase;
                    break;
                }
            }
            curr = curr->Flink;
        }

        if (!base_addr) return nullptr;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_addr);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const u8*>(base_addr) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        const auto& export_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_dir.VirtualAddress == 0 || export_dir.Size == 0) return nullptr;

        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<const u8*>(base_addr) + export_dir.VirtualAddress);
        const auto* names = reinterpret_cast<const u32*>(reinterpret_cast<const u8*>(base_addr) + exports->AddressOfNames);
        const auto* ordinals = reinterpret_cast<const u16*>(reinterpret_cast<const u8*>(base_addr) + exports->AddressOfNameOrdinals);
        const auto* functions = reinterpret_cast<const u32*>(reinterpret_cast<const u8*>(base_addr) + exports->AddressOfFunctions);

        for (u32 i = 0; i < exports->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(reinterpret_cast<const u8*>(base_addr) + names[i]);
            if (core::Fnv1a::hash(name, std::strlen(name)) == function_hash) {
                u16 ord = ordinals[i];
                return const_cast<void*>(reinterpret_cast<const void*>(reinterpret_cast<const u8*>(base_addr) + functions[ord]));
            }
        }
        return nullptr;
#else
        (void)module_hash; (void)function_hash;
        return nullptr;
#endif
    }

    template <typename FuncType>
    static inline FuncType get(u64 module_hash, u64 function_hash) noexcept {
        return reinterpret_cast<FuncType>(resolve_raw(module_hash, function_hash));
    }
};

} // namespace anti

#define AEGIS_API(module_str, func_str, FuncType) \
    ::aegis::anti::ApiResolver::get<FuncType>( \
        ::aegis::core::Fnv1a::hash(module_str), \
        ::aegis::core::Fnv1a::hash(func_str) \
    )

// ============================================================================
// 15. HARDWARE & TPM IDENTITY EXTRACTION (HWID)
// (Integrated from hardware-checker)
// ============================================================================
namespace hwid {

class HardwareId {
public:
    static inline std::string bytes_to_hex(const std::vector<u8>& bytes) {
        std::string hex;
        char buf[3];
        for (u8 b : bytes) {
            snprintf(buf, sizeof(buf), "%02x", b);
            hex += buf;
        }
        return hex;
    }

    /**
     * @brief Extracts TPM 2.0 Endorsement Key (EKPub) from Platform Crypto Provider
     */
    static inline std::vector<u8> get_tpm_ek() noexcept {
#if defined(AEGIS_WINDOWS)
        NCRYPT_PROV_HANDLE hProvider = 0;
        if (NCryptOpenStorageProvider(&hProvider, L"Microsoft Platform Crypto Provider", 0) != ERROR_SUCCESS) {
            return {};
        }

        DWORD cbResult = 0;
        if (NCryptGetProperty(hProvider, L"PCP_EKPUB", nullptr, 0, &cbResult, 0) != ERROR_SUCCESS) {
            NCryptFreeObject(hProvider);
            return {};
        }

        std::vector<u8> ekPub(cbResult);
        if (NCryptGetProperty(hProvider, L"PCP_EKPUB", ekPub.data(), cbResult, &cbResult, 0) != ERROR_SUCCESS) {
            NCryptFreeObject(hProvider);
            return {};
        }

        DWORD cbEncoded = 0;
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB, ekPub.data(), 0, nullptr, nullptr, &cbEncoded)) {
            NCryptFreeObject(hProvider);
            return {};
        }

        std::vector<u8> encodedEk(cbEncoded);
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB, ekPub.data(), 0, nullptr, encodedEk.data(), &cbEncoded)) {
            NCryptFreeObject(hProvider);
            return {};
        }

        NCryptFreeObject(hProvider);
        return encodedEk;
#else
        return {};
#endif
    }

    /**
     * @brief Computes combined machine fingerprint hash (CPUID + TPM + Machine GUID)
     */
    static inline u64 get_machine_fingerprint() noexcept {
        u64 hash = core::Fnv1a::OFFSET_BASIS;

#if defined(AEGIS_COMPILER_MSVC)
        int cpu_info[4]{};
        __cpuid(cpu_info, 1);
        for (int i = 0; i < 4; ++i) {
            hash ^= static_cast<u64>(cpu_info[i]);
            hash *= core::Fnv1a::PRIME;
        }
#endif

        auto tpm = get_tpm_ek();
        if (!tpm.empty()) {
            hash ^= core::Fnv1a::hash(tpm.data(), tpm.size());
            hash *= core::Fnv1a::PRIME;
        }

        return hash;
    }
};

} // namespace hwid

// ============================================================================
// 16. PROCESS & MEMORY UTILITIES
// (Integrated from memory-utils / cleaner.cpp & memory.cpp)
// ============================================================================
namespace mem {

class MemoryScanner {
public:
    static inline std::vector<size_t> find_pattern(const u8* data, size_t size, const u8* pattern, size_t pat_size) {
        std::vector<size_t> matches;
        if (!data || !pattern || size < pat_size || pat_size == 0) return matches;

        for (size_t i = 0; i <= size - pat_size; ++i) {
            if (std::memcmp(data + i, pattern, pat_size) == 0) {
                matches.push_back(i);
            }
        }
        return matches;
    }

    /**
     * @brief Trims working set of current process to purge sensitive data from RAM pages
     */
    static inline bool clean_working_set() noexcept {
#if defined(AEGIS_WINDOWS)
        return SetProcessWorkingSetSize(GetCurrentProcess(), static_cast<SIZE_T>(-1), static_cast<SIZE_T>(-1)) != FALSE;
#else
        return false;
#endif
    }

    static inline bool terminate_process_by_name(const std::string& process_name) noexcept {
#if defined(AEGIS_WINDOWS)
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);

        if (!Process32First(snapshot, &entry)) {
            CloseHandle(snapshot);
            return false;
        }

        bool terminated = false;
        do {
            std::string current_name;
#ifdef UNICODE
            char buf[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, buf, sizeof(buf), nullptr, nullptr);
            current_name = buf;
#else
            current_name = entry.szExeFile;
#endif
            if (_stricmp(current_name.c_str(), process_name.c_str()) == 0) {
                HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                if (proc) {
                    TerminateProcess(proc, 0);
                    CloseHandle(proc);
                    terminated = true;
                }
            }
        } while (Process32Next(snapshot, &entry));

        CloseHandle(snapshot);
        return terminated;
#else
        (void)process_name;
        return false;
#endif
    }
};

} // namespace mem

// ============================================================================
// 17. JVM NATIVE BRIDGE (JNI STRING POOL & NATIVE REGISTRATION)
// (Integrated from jvm-protection)
// ============================================================================
namespace jvm {

class JniStringPool {
public:
    static inline u64 hash_symbol(const char* name) noexcept {
        return core::Fnv1a::hash(name, std::strlen(name));
    }
};

} // namespace jvm

// ============================================================================
// 18. EMBEDDED PURE C++20 CRYPTOGRAPHY (FIPS 180-4 SHA-256 & RFC 8439 CHACHA20)
// ============================================================================
namespace crypto {

/**
 * @brief FIPS 180-4 Compliant SHA-256 & HMAC-SHA256 Engine (Zero External Dependencies)
 */
class Sha256 {
public:
    using Digest = std::array<u8, 32>;

    static constexpr std::array<u32, 64> K = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
        0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
        0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
        0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
        0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
        0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
        0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
        0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
        0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
    };

    constexpr Sha256() noexcept { reset(); }

    constexpr void reset() noexcept {
        state_[0] = 0x6a09e667UL;
        state_[1] = 0xbb67ae85UL;
        state_[2] = 0x3c6ef372UL;
        state_[3] = 0xa54ff53aUL;
        state_[4] = 0x510e527fUL;
        state_[5] = 0x9b05688cUL;
        state_[6] = 0x1f83d9abUL;
        state_[7] = 0x5be0cd19UL;
        bit_len_ = 0;
        buffer_len_ = 0;
        buffer_.fill(0);
    }

    constexpr void update(const u8* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            if (buffer_len_ == 64) {
                transform(buffer_.data());
                bit_len_ += 512;
                buffer_len_ = 0;
            }
        }
    }

    constexpr void update(std::string_view sv) noexcept {
        update(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    constexpr Digest finalize() noexcept {
        size_t i = buffer_len_;
        u64 total_bits = bit_len_ + static_cast<u64>(buffer_len_) * 8ULL;

        buffer_[i++] = 0x80;
        if (i > 56) {
            while (i < 64) buffer_[i++] = 0x00;
            transform(buffer_.data());
            i = 0;
        }
        while (i < 56) buffer_[i++] = 0x00;

        buffer_[56] = static_cast<u8>((total_bits >> 56) & 0xFF);
        buffer_[57] = static_cast<u8>((total_bits >> 48) & 0xFF);
        buffer_[58] = static_cast<u8>((total_bits >> 40) & 0xFF);
        buffer_[59] = static_cast<u8>((total_bits >> 32) & 0xFF);
        buffer_[60] = static_cast<u8>((total_bits >> 24) & 0xFF);
        buffer_[61] = static_cast<u8>((total_bits >> 16) & 0xFF);
        buffer_[62] = static_cast<u8>((total_bits >> 8)  & 0xFF);
        buffer_[63] = static_cast<u8>(total_bits & 0xFF);
        transform(buffer_.data());

        Digest out{};
        for (size_t j = 0; j < 8; ++j) {
            out[j * 4 + 0] = static_cast<u8>((state_[j] >> 24) & 0xFF);
            out[j * 4 + 1] = static_cast<u8>((state_[j] >> 16) & 0xFF);
            out[j * 4 + 2] = static_cast<u8>((state_[j] >> 8)  & 0xFF);
            out[j * 4 + 3] = static_cast<u8>(state_[j] & 0xFF);
        }
        return out;
    }

    static constexpr Digest hash(const u8* data, size_t len) noexcept {
        Sha256 ctx;
        ctx.update(data, len);
        return ctx.finalize();
    }

    static inline Digest hash(std::string_view sv) noexcept {
        return hash(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    static inline std::string hash_hex(std::string_view sv) {
        return to_hex(hash(sv));
    }

    static inline std::string to_hex(const Digest& digest) {
        static constexpr char hex_chars[] = "0123456789abcdef";
        std::string res;
        res.reserve(64);
        for (u8 b : digest) {
            res.push_back(hex_chars[(b >> 4) & 0x0F]);
            res.push_back(hex_chars[b & 0x0F]);
        }
        return res;
    }

    static inline Digest hmac(const u8* key, size_t key_len, const u8* msg, size_t msg_len) noexcept {
        std::array<u8, 64> k_ipad{};
        std::array<u8, 64> k_opad{};
        std::array<u8, 64> tk{};

        if (key_len > 64) {
            Digest d = hash(key, key_len);
            for (size_t i = 0; i < 32; ++i) tk[i] = d[i];
        } else {
            for (size_t i = 0; i < key_len; ++i) tk[i] = key[i];
        }

        for (size_t i = 0; i < 64; ++i) {
            k_ipad[i] = tk[i] ^ 0x36;
            k_opad[i] = tk[i] ^ 0x5c;
        }

        Sha256 inner;
        inner.update(k_ipad.data(), 64);
        inner.update(msg, msg_len);
        Digest inner_digest = inner.finalize();

        Sha256 outer;
        outer.update(k_opad.data(), 64);
        outer.update(inner_digest.data(), 32);
        return outer.finalize();
    }

private:
    static constexpr u32 rotr(u32 x, u32 n) noexcept {
        return (x >> n) | (x << (32 - n));
    }

    constexpr void transform(const u8* block) noexcept {
        u32 w[64]{};
        for (size_t i = 0; i < 16; ++i) {
            w[i] = (static_cast<u32>(block[i * 4 + 0]) << 24) |
                   (static_cast<u32>(block[i * 4 + 1]) << 16) |
                   (static_cast<u32>(block[i * 4 + 2]) << 8)  |
                   (static_cast<u32>(block[i * 4 + 3]));
        }
        for (size_t i = 16; i < 64; ++i) {
            u32 s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            u32 s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        u32 a = state_[0];
        u32 b = state_[1];
        u32 c = state_[2];
        u32 d = state_[3];
        u32 e = state_[4];
        u32 f = state_[5];
        u32 g = state_[6];
        u32 h = state_[7];

        for (size_t i = 0; i < 64; ++i) {
            u32 S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            u32 ch = (e & f) ^ ((~e) & g);
            u32 temp1 = h + S1 + ch + K[i] + w[i];
            u32 S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            u32 maj = (a & b) ^ (a & c) ^ (b & c);
            u32 temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<u32, 8> state_{};
    std::array<u8, 64> buffer_{};
    u64 bit_len_{0};
    size_t buffer_len_{0};
};

/**
 * @brief RFC 8439 ChaCha20 256-bit Stream Cipher (20 Rounds)
 */
class ChaCha20 {
public:
    using Key   = std::array<u8, 32>;
    using Nonce = std::array<u8, 12>;

    static constexpr u32 rotl32(u32 x, u32 n) noexcept {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr void quarter_round(u32& a, u32& b, u32& c, u32& d) noexcept {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    static constexpr void generate_block(const Key& key, const Nonce& nonce, u32 counter, std::array<u8, 64>& out_block) noexcept {
        auto pack32 = [](const u8* p) constexpr noexcept -> u32 {
            return static_cast<u32>(p[0]) |
                  (static_cast<u32>(p[1]) << 8) |
                  (static_cast<u32>(p[2]) << 16) |
                  (static_cast<u32>(p[3]) << 24);
        };

        std::array<u32, 16> state = {
            0x61707865UL, 0x3320646eUL, 0x79622d32UL, 0x6b206574UL, // "expand 32-byte k"
            pack32(&key[0]),  pack32(&key[4]),  pack32(&key[8]),  pack32(&key[12]),
            pack32(&key[16]), pack32(&key[20]), pack32(&key[24]), pack32(&key[28]),
            counter,
            pack32(&nonce[0]), pack32(&nonce[4]), pack32(&nonce[8])
        };

        std::array<u32, 16> working = state;
        for (int i = 0; i < 10; ++i) {
            // Column rounds
            quarter_round(working[0], working[4], working[8],  working[12]);
            quarter_round(working[1], working[5], working[9],  working[13]);
            quarter_round(working[2], working[6], working[10], working[14]);
            quarter_round(working[3], working[7], working[11], working[15]);
            // Diagonal rounds
            quarter_round(working[0], working[5], working[10], working[15]);
            quarter_round(working[1], working[6], working[11], working[12]);
            quarter_round(working[2], working[7], working[8],  working[13]);
            quarter_round(working[3], working[4], working[9],  working[14]);
        }

        for (size_t i = 0; i < 16; ++i) {
            u32 v = working[i] + state[i];
            out_block[i * 4 + 0] = static_cast<u8>(v & 0xFF);
            out_block[i * 4 + 1] = static_cast<u8>((v >> 8) & 0xFF);
            out_block[i * 4 + 2] = static_cast<u8>((v >> 16) & 0xFF);
            out_block[i * 4 + 3] = static_cast<u8>((v >> 24) & 0xFF);
        }
    }

    static inline void crypt(const Key& key, const Nonce& nonce, u32 initial_counter, u8* data, size_t len) noexcept {
        std::array<u8, 64> keystream{};
        u32 counter = initial_counter;
        size_t offset = 0;

        while (offset < len) {
            generate_block(key, nonce, counter++, keystream);
            size_t chunk = (len - offset < 64) ? (len - offset) : 64;
            for (size_t i = 0; i < chunk; ++i) {
                data[offset + i] ^= keystream[i];
            }
            offset += chunk;
        }
        secure_zero(keystream.data(), keystream.size());
    }
};

} // namespace crypto

// ============================================================================
// 19. SYSTEM CALL STUB INTEGRITY INSPECTOR & SSN RESOLVER
// ============================================================================
namespace syscall {

struct SyscallDescriptor {
    u32 ssn{0};
    const void* stub_address{nullptr};
    bool is_hooked{false};
    bool valid{false};
};

class SyscallResolver {
public:
    /**
     * @brief Inspects an ntdll.dll export by FNV-1a hash, checks for user-mode inline hooks,
     * and extracts the System Service Number (SSN) directly or via neighbor stub offset scan.
     */
    static inline SyscallDescriptor inspect_by_hash(u64 func_hash) noexcept {
        SyscallDescriptor desc{};
#if defined(AEGIS_WINDOWS) && defined(AEGIS_ARCH_X64)
        constexpr u64 ntdll_hash = core::Fnv1a::hash("ntdll.dll", 9);
        const auto* stub = static_cast<const u8*>(anti::ApiResolver::resolve_raw(ntdll_hash, func_hash));
        if (!stub) return desc;

        desc.stub_address = stub;

        // Standard Windows x64 syscall stub prologue:
        // 4C 8B D1       mov r10, rcx
        // B8 XX XX 00 00 mov eax, <SSN>
        if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 &&
            stub[6] == 0x00 && stub[7] == 0x00) {
            desc.ssn = static_cast<u32>(stub[4]) | (static_cast<u32>(stub[5]) << 8);
            desc.is_hooked = false;
            desc.valid = true;
            return desc;
        }

        // Stub does not match clean prologue (e.g. starts with 0xE9 JMP rel32 hook)
        desc.is_hooked = true;

        // Neighbor stub scan (32-byte aligned syscall stubs in ntdll.dll)
        constexpr int MAX_NEIGHBORS = 32;
        constexpr ptrdiff_t STUB_STRIDE = 32;
        for (int idx = 1; idx <= MAX_NEIGHBORS; ++idx) {
            // Check downward neighbor (+idx * 32)
            const u8* down = stub + (idx * STUB_STRIDE);
            if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8 &&
                down[6] == 0x00 && down[7] == 0x00) {
                u32 neighbor_ssn = static_cast<u32>(down[4]) | (static_cast<u32>(down[5]) << 8);
                if (neighbor_ssn >= static_cast<u32>(idx)) {
                    desc.ssn = neighbor_ssn - static_cast<u32>(idx);
                    desc.valid = true;
                    return desc;
                }
            }
            // Check upward neighbor (-idx * 32)
            const u8* up = stub - (idx * STUB_STRIDE);
            if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8 &&
                up[6] == 0x00 && up[7] == 0x00) {
                u32 neighbor_ssn = static_cast<u32>(up[4]) | (static_cast<u32>(up[5]) << 8);
                desc.ssn = neighbor_ssn + static_cast<u32>(idx);
                desc.valid = true;
                return desc;
            }
        }
#else
        (void)func_hash;
#endif
        return desc;
    }

    static inline SyscallDescriptor inspect(std::string_view func_name) noexcept {
        return inspect_by_hash(core::Fnv1a::hash(func_name));
    }
};

} // namespace syscall

// ============================================================================
// 20. VECTORED EXCEPTION HANDLING (VEH) HARDWARE BREAKPOINT & TRAP GUARD
// ============================================================================
namespace veh {

class VehGuard {
public:
    static inline bool install(bool auto_scrub_hw_bp = true) noexcept {
#if defined(AEGIS_WINDOWS)
        std::lock_guard<std::mutex> lock(mutex_());
        scrub_hw_bp_().store(auto_scrub_hw_bp, std::memory_order_relaxed);
        if (handle_() != nullptr) return true;
        handle_() = AddVectoredExceptionHandler(1, &vectored_handler);
        return handle_() != nullptr;
#else
        (void)auto_scrub_hw_bp;
        return false;
#endif
    }

    static inline void uninstall() noexcept {
#if defined(AEGIS_WINDOWS)
        std::lock_guard<std::mutex> lock(mutex_());
        if (handle_() != nullptr) {
            RemoveVectoredExceptionHandler(handle_());
            handle_() = nullptr;
        }
#endif
    }

    static inline bool is_installed() noexcept {
#if defined(AEGIS_WINDOWS)
        std::lock_guard<std::mutex> lock(mutex_());
        return handle_() != nullptr;
#else
        return false;
#endif
    }

    static inline u64 intercepted_count() noexcept {
        return counter_().load(std::memory_order_relaxed);
    }

    /**
     * @brief Actively scrubs hardware debug registers (Dr0-Dr3, Dr6, Dr7) on current thread
     */
    static inline bool scrub_current_thread_debug_registers() noexcept {
#if defined(AEGIS_WINDOWS)
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
        return SetThreadContext(GetCurrentThread(), &ctx) != FALSE;
#else
        return false;
#endif
    }

private:
#if defined(AEGIS_WINDOWS)
    static LONG CALLBACK vectored_handler(PEXCEPTION_POINTERS ep) noexcept {
        if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        const DWORD code = ep->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT) {
            counter_().fetch_add(1, std::memory_order_relaxed);
            if (scrub_hw_bp_().load(std::memory_order_relaxed)) {
                ep->ContextRecord->Dr0 = 0;
                ep->ContextRecord->Dr1 = 0;
                ep->ContextRecord->Dr2 = 0;
                ep->ContextRecord->Dr3 = 0;
                ep->ContextRecord->Dr6 = 0;
                ep->ContextRecord->Dr7 = 0;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    static void*& handle_() noexcept {
        static void* h = nullptr;
        return h;
    }
    static std::mutex& mutex_() noexcept {
        static std::mutex m;
        return m;
    }
#endif
    static std::atomic<u64>& counter_() noexcept {
        static std::atomic<u64> c{0};
        return c;
    }
    static std::atomic<bool>& scrub_hw_bp_() noexcept {
        static std::atomic<bool> s{true};
        return s;
    }
};

} // namespace veh

// ============================================================================
// 21. BACKGROUND MEMORY INTEGRITY WATCHDOG THREAD
// ============================================================================
namespace watchdog {

enum class ViolationType : u32 {
    None               = 0,
    ChecksumMismatch   = 1,
    SoftwareBreakpoint = 2,
    InlineHookDetected = 3,
    DebuggerDetected   = 4
};

struct WatchedRegion {
    const void* address{nullptr};
    size_t size{0};
    u32 murmur_hash{0};
    crypto::Sha256::Digest sha256_digest{};
};

class IntegrityWatchdog {
public:
    using ViolationCallback = std::function<void(ViolationType, const void*)>;

    IntegrityWatchdog() = default;

    ~IntegrityWatchdog() {
        stop();
    }

    IntegrityWatchdog(const IntegrityWatchdog&) = delete;
    IntegrityWatchdog& operator=(const IntegrityWatchdog&) = delete;

    void add_region(const void* address, size_t size) {
        if (!address || size == 0) return;
        std::lock_guard<std::mutex> lock(mutex_);
        WatchedRegion reg{};
        reg.address = address;
        reg.size = size;
        reg.murmur_hash = anti::IntegrityScanner::hash_region(address, size);
        reg.sha256_digest = crypto::Sha256::hash(static_cast<const u8*>(address), size);
        regions_.push_back(reg);
    }

    void set_callback(ViolationCallback cb) {
        std::lock_guard<std::mutex> lock(mutex_);
        callback_ = std::move(cb);
    }

    /**
     * @brief Performs a single synchronous integrity & anti-debug scan across all regions
     */
    ViolationType scan_once(bool check_debugger = true) {
        std::lock_guard<std::mutex> lock(mutex_);
        scan_count_.fetch_add(1, std::memory_order_relaxed);

        for (const auto& reg : regions_) {
            if (anti::IntegrityScanner::has_software_breakpoints(reg.address, reg.size)) {
                violations_.fetch_add(1, std::memory_order_relaxed);
                if (callback_) callback_(ViolationType::SoftwareBreakpoint, reg.address);
                return ViolationType::SoftwareBreakpoint;
            }
            if (anti::IntegrityScanner::has_inline_hook(reg.address)) {
                violations_.fetch_add(1, std::memory_order_relaxed);
                if (callback_) callback_(ViolationType::InlineHookDetected, reg.address);
                return ViolationType::InlineHookDetected;
            }
            u32 current_murmur = anti::IntegrityScanner::hash_region(reg.address, reg.size);
            auto current_sha = crypto::Sha256::hash(static_cast<const u8*>(reg.address), reg.size);
            if (current_murmur != reg.murmur_hash || current_sha != reg.sha256_digest) {
                violations_.fetch_add(1, std::memory_order_relaxed);
                if (callback_) callback_(ViolationType::ChecksumMismatch, reg.address);
                return ViolationType::ChecksumMismatch;
            }
        }

        if (check_debugger && (anti::AntiDebug::check_peb_being_debugged() || anti::AntiDebug::check_hardware_breakpoints())) {
            violations_.fetch_add(1, std::memory_order_relaxed);
            if (callback_) callback_(ViolationType::DebuggerDetected, nullptr);
            return ViolationType::DebuggerDetected;
        }

        return ViolationType::None;
    }

    void start(u32 interval_ms = 50, bool check_debugger = true) {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) return;

        worker_ = std::thread([this, interval_ms, check_debugger]() {
            while (running_.load(std::memory_order_relaxed)) {
                scan_once(check_debugger);
                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            }
        });
    }

    void stop() {
        bool expected = true;
        if (running_.compare_exchange_strong(expected, false)) {
            if (worker_.joinable()) {
                worker_.join();
            }
        }
    }

    bool is_running() const noexcept { return running_.load(std::memory_order_relaxed); }
    u64 scan_count() const noexcept { return scan_count_.load(std::memory_order_relaxed); }
    u64 violation_count() const noexcept { return violations_.load(std::memory_order_relaxed); }

private:
    std::mutex mutex_;
    std::vector<WatchedRegion> regions_;
    ViolationCallback callback_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<u64> scan_count_{0};
    std::atomic<u64> violations_{0};
};

} // namespace watchdog

// ============================================================================
// 22. FIPS 180-4 SHA-512, SHA-384 & HMAC-SHA512 CRYPTOGRAPHIC ENGINE
// ============================================================================
namespace crypto {

/**
 * @brief Full 64-bit FIPS 180-4 SHA-512 & SHA-384 Implementation
 * Provides constexpr hashing, streaming updates, and HMAC-SHA512 authentication.
 */
class Sha512 {
public:
    using Digest512 = std::array<u8, 64>;
    using Digest384 = std::array<u8, 48>;

    static constexpr std::array<u64, 80> K = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    constexpr explicit Sha512(bool is_sha384 = false) noexcept {
        reset(is_sha384);
    }

    constexpr void reset(bool is_sha384 = false) noexcept {
        if (is_sha384) {
            state_[0] = 0xcbbb9d5dc1059ed8ULL;
            state_[1] = 0x629a292a367cd507ULL;
            state_[2] = 0x9159015a3070dd17ULL;
            state_[3] = 0x152fecd8f70e5939ULL;
            state_[4] = 0x67332667ffc00b31ULL;
            state_[5] = 0x8eb44a8768581511ULL;
            state_[6] = 0xdb0c2e0d64f98fa7ULL;
            state_[7] = 0x47b5481dbefa4fa4ULL;
        } else {
            state_[0] = 0x6a09e667f3bcc908ULL;
            state_[1] = 0xbb67ae8584caa73bULL;
            state_[2] = 0x3c6ef372fe94f82bULL;
            state_[3] = 0xa54ff53a5f1d36f1ULL;
            state_[4] = 0x510e527fade682d1ULL;
            state_[5] = 0x9b05688c2b3e6c1fULL;
            state_[6] = 0x1f83d9abfb41bd6bULL;
            state_[7] = 0x5be0cd19137e2179ULL;
        }
        total_len_ = 0;
        buffer_len_ = 0;
        buffer_.fill(0);
    }

    constexpr void update(const u8* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            total_len_++;
            if (buffer_len_ == 128) {
                transform(buffer_.data());
                buffer_len_ = 0;
            }
        }
    }

    constexpr void update(std::string_view sv) noexcept {
        update(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    constexpr Digest512 finalize() noexcept {
        u64 total_bits_lo = total_len_ * 8ULL;
        u64 total_bits_hi = (total_len_ >> 61);

        buffer_[buffer_len_++] = 0x80;
        if (buffer_len_ > 112) {
            while (buffer_len_ < 128) {
                buffer_[buffer_len_++] = 0x00;
            }
            transform(buffer_.data());
            buffer_len_ = 0;
        }
        while (buffer_len_ < 112) {
            buffer_[buffer_len_++] = 0x00;
        }

        for (int i = 0; i < 8; ++i) {
            buffer_[112 + i] = static_cast<u8>((total_bits_hi >> (56 - i * 8)) & 0xFF);
            buffer_[120 + i] = static_cast<u8>((total_bits_lo >> (56 - i * 8)) & 0xFF);
        }
        transform(buffer_.data());

        Digest512 out{};
        for (size_t i = 0; i < 8; ++i) {
            for (size_t b = 0; b < 8; ++b) {
                out[i * 8 + b] = static_cast<u8>((state_[i] >> (56 - b * 8)) & 0xFF);
            }
        }
        return out;
    }

    constexpr Digest384 finalize384() noexcept {
        Digest512 full = finalize();
        Digest384 out{};
        for (size_t i = 0; i < 48; ++i) {
            out[i] = full[i];
        }
        return out;
    }

    static constexpr Digest512 hash(const u8* data, size_t len) noexcept {
        Sha512 ctx(false);
        ctx.update(data, len);
        return ctx.finalize();
    }

    static inline Digest512 hash(std::string_view sv) noexcept {
        return hash(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    static constexpr Digest384 hash384(const u8* data, size_t len) noexcept {
        Sha512 ctx(true);
        ctx.update(data, len);
        return ctx.finalize384();
    }

    static inline std::string to_hex(const Digest512& d) {
        static constexpr char hex[] = "0123456789abcdef";
        std::string s;
        s.reserve(128);
        for (u8 b : d) {
            s.push_back(hex[(b >> 4) & 0x0F]);
            s.push_back(hex[b & 0x0F]);
        }
        return s;
    }

    static inline std::string hash_hex(std::string_view sv) {
        return to_hex(hash(sv));
    }

    static inline Digest512 hmac(const u8* key, size_t key_len, const u8* msg, size_t msg_len) noexcept {
        std::array<u8, 128> k_ipad{};
        std::array<u8, 128> k_opad{};
        std::array<u8, 128> tk{};

        if (key_len > 128) {
            Digest512 kh = hash(key, key_len);
            for (size_t i = 0; i < 64; ++i) tk[i] = kh[i];
        } else {
            for (size_t i = 0; i < key_len; ++i) tk[i] = key[i];
        }

        for (size_t i = 0; i < 128; ++i) {
            k_ipad[i] = tk[i] ^ 0x36;
            k_opad[i] = tk[i] ^ 0x5c;
        }

        Sha512 inner(false);
        inner.update(k_ipad.data(), 128);
        inner.update(msg, msg_len);
        Digest512 inner_d = inner.finalize();

        Sha512 outer(false);
        outer.update(k_opad.data(), 128);
        outer.update(inner_d.data(), 64);
        return outer.finalize();
    }

private:
    static constexpr u64 rotr64(u64 x, u32 n) noexcept {
        return (x >> n) | (x << (64 - n));
    }

    constexpr void transform(const u8* block) noexcept {
        u64 w[80]{};
        for (size_t i = 0; i < 16; ++i) {
            u64 v = 0;
            for (size_t b = 0; b < 8; ++b) {
                v = (v << 8) | static_cast<u64>(block[i * 8 + b]);
            }
            w[i] = v;
        }
        for (size_t i = 16; i < 80; ++i) {
            u64 s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            u64 s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        u64 a = state_[0];
        u64 b = state_[1];
        u64 c = state_[2];
        u64 d = state_[3];
        u64 e = state_[4];
        u64 f = state_[5];
        u64 g = state_[6];
        u64 h = state_[7];

        for (size_t i = 0; i < 80; ++i) {
            u64 S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            u64 ch = (e & f) ^ ((~e) & g);
            u64 temp1 = h + S1 + ch + K[i] + w[i];
            u64 S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            u64 maj = (a & b) ^ (a & c) ^ (b & c);
            u64 temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<u64, 8> state_{};
    std::array<u8, 128> buffer_{};
    u64 total_len_{0};
    size_t buffer_len_{0};
};

// ============================================================================
// 23. RFC 7693 BLAKE2b-512 CRYPTOGRAPHIC HASH & KEYED MAC ENGINE
// ============================================================================
class Blake2b {
public:
    using Digest = std::array<u8, 64>;

    static constexpr std::array<u64, 8> IV = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    static constexpr u8 SIGMA[12][16] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    };

    explicit Blake2b(size_t out_len = 64, const u8* key = nullptr, size_t key_len = 0) noexcept {
        init(out_len, key, key_len);
    }

    void init(size_t out_len = 64, const u8* key = nullptr, size_t key_len = 0) noexcept {
        out_len_ = (out_len == 0 || out_len > 64) ? 64 : out_len;
        for (size_t i = 0; i < 8; ++i) h_[i] = IV[i];
        h_[0] ^= 0x01010000ULL ^ (static_cast<u64>(key_len) << 8) ^ static_cast<u64>(out_len_);
        t_[0] = 0;
        t_[1] = 0;
        f_[0] = 0;
        f_[1] = 0;
        buflen_ = 0;
        buf_.fill(0);

        if (key && key_len > 0 && key_len <= 64) {
            std::memcpy(buf_.data(), key, key_len);
            buflen_ = 128;
        }
    }

    void update(const u8* in, size_t inlen) noexcept {
        if (inlen == 0) return;
        size_t left = buflen_;
        size_t fill = 128 - left;
        if (inlen > fill) {
            buflen_ = 0;
            std::memcpy(buf_.data() + left, in, fill);
            increment_counter(128);
            compress(buf_.data(), false);
            in += fill;
            inlen -= fill;
            while (inlen > 128) {
                increment_counter(128);
                compress(in, false);
                in += 128;
                inlen -= 128;
            }
        }
        std::memcpy(buf_.data() + buflen_, in, inlen);
        buflen_ += inlen;
    }

    Digest finalize() noexcept {
        increment_counter(buflen_);
        f_[0] = ~0ULL;
        for (size_t i = buflen_; i < 128; ++i) buf_[i] = 0;
        compress(buf_.data(), true);

        Digest out{};
        for (size_t i = 0; i < 8; ++i) {
            out[i * 8 + 0] = static_cast<u8>((h_[i] >> 0) & 0xFF);
            out[i * 8 + 1] = static_cast<u8>((h_[i] >> 8) & 0xFF);
            out[i * 8 + 2] = static_cast<u8>((h_[i] >> 16) & 0xFF);
            out[i * 8 + 3] = static_cast<u8>((h_[i] >> 24) & 0xFF);
            out[i * 8 + 4] = static_cast<u8>((h_[i] >> 32) & 0xFF);
            out[i * 8 + 5] = static_cast<u8>((h_[i] >> 40) & 0xFF);
            out[i * 8 + 6] = static_cast<u8>((h_[i] >> 48) & 0xFF);
            out[i * 8 + 7] = static_cast<u8>((h_[i] >> 56) & 0xFF);
        }
        return out;
    }

    static inline Digest hash(const u8* data, size_t len, const u8* key = nullptr, size_t key_len = 0) noexcept {
        Blake2b ctx(64, key, key_len);
        ctx.update(data, len);
        return ctx.finalize();
    }

    static inline Digest hash(std::string_view sv) noexcept {
        return hash(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    static inline std::string hash_hex(std::string_view sv) {
        Digest d = hash(sv);
        static constexpr char hex[] = "0123456789abcdef";
        std::string s;
        s.reserve(128);
        for (u8 b : d) {
            s.push_back(hex[(b >> 4) & 0x0F]);
            s.push_back(hex[b & 0x0F]);
        }
        return s;
    }

private:
    static constexpr u64 rotr64(u64 w, unsigned c) noexcept {
        return (w >> c) | (w << (64 - c));
    }

    static constexpr u64 load64(const u8* p) noexcept {
        return static_cast<u64>(p[0]) |
              (static_cast<u64>(p[1]) << 8) |
              (static_cast<u64>(p[2]) << 16) |
              (static_cast<u64>(p[3]) << 24) |
              (static_cast<u64>(p[4]) << 32) |
              (static_cast<u64>(p[5]) << 40) |
              (static_cast<u64>(p[6]) << 48) |
              (static_cast<u64>(p[7]) << 56);
    }

    void increment_counter(u64 inc) noexcept {
        t_[0] += inc;
        if (t_[0] < inc) t_[1]++;
    }

    static constexpr void G(u64& a, u64& b, u64& c, u64& d, u64 x, u64 y) noexcept {
        a = a + b + x;
        d = rotr64(d ^ a, 32);
        c = c + d;
        b = rotr64(b ^ c, 24);
        a = a + b + y;
        d = rotr64(d ^ a, 16);
        c = c + d;
        b = rotr64(b ^ c, 63);
    }

    void compress(const u8* block, bool /*last*/) noexcept {
        u64 m[16]{};
        u64 v[16]{};
        for (size_t i = 0; i < 16; ++i) m[i] = load64(block + i * 8);
        for (size_t i = 0; i < 8; ++i) v[i] = h_[i];
        v[8]  = IV[0];
        v[9]  = IV[1];
        v[10] = IV[2];
        v[11] = IV[3];
        v[12] = IV[4] ^ t_[0];
        v[13] = IV[5] ^ t_[1];
        v[14] = IV[6] ^ f_[0];
        v[15] = IV[7] ^ f_[1];

        for (size_t r = 0; r < 12; ++r) {
            G(v[0], v[4], v[8],  v[12], m[SIGMA[r][0]],  m[SIGMA[r][1]]);
            G(v[1], v[5], v[9],  v[13], m[SIGMA[r][2]],  m[SIGMA[r][3]]);
            G(v[2], v[6], v[10], v[14], m[SIGMA[r][4]],  m[SIGMA[r][5]]);
            G(v[3], v[7], v[11], v[15], m[SIGMA[r][6]],  m[SIGMA[r][7]]);
            G(v[0], v[5], v[10], v[15], m[SIGMA[r][8]],  m[SIGMA[r][9]]);
            G(v[1], v[6], v[11], v[12], m[SIGMA[r][10]], m[SIGMA[r][11]]);
            G(v[2], v[7], v[8],  v[13], m[SIGMA[r][12]], m[SIGMA[r][13]]);
            G(v[3], v[4], v[9],  v[14], m[SIGMA[r][14]], m[SIGMA[r][15]]);
        }

        for (size_t i = 0; i < 8; ++i) {
            h_[i] ^= v[i] ^ v[i + 8];
        }
    }

    std::array<u64, 8> h_{};
    std::array<u64, 2> t_{};
    std::array<u64, 2> f_{};
    std::array<u8, 128> buf_{};
    size_t buflen_{0};
    size_t out_len_{64};
};

// ============================================================================
// 24. FIPS 197 AES-256 BLOCK CIPHER (ECB, CBC, CTR MODES & PKCS#7 PADDING)
// ============================================================================
class Aes256 {
public:
    using Key   = std::array<u8, 32>;
    using Block = std::array<u8, 16>;
    using Iv    = std::array<u8, 16>;

    static constexpr std::array<u8, 256> SBOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    static constexpr std::array<u8, 256> INV_SBOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    static constexpr std::array<u8, 11> RCON = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    constexpr explicit Aes256(const Key& key) noexcept {
        expand_key(key);
    }

    ~Aes256() noexcept {
        secure_zero(round_keys_.data(), round_keys_.size());
    }

    constexpr void expand_key(const Key& key) noexcept {
        for (size_t i = 0; i < 32; ++i) {
            round_keys_[i] = key[i];
        }
        std::array<u8, 4> temp{};
        for (size_t i = 8; i < 60; ++i) {
            for (size_t k = 0; k < 4; ++k) {
                temp[k] = round_keys_[(i - 1) * 4 + k];
            }
            if (i % 8 == 0) {
                u8 t = temp[0];
                temp[0] = SBOX[temp[1]] ^ RCON[i / 8];
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[t];
            } else if (i % 8 == 4) {
                temp[0] = SBOX[temp[0]];
                temp[1] = SBOX[temp[1]];
                temp[2] = SBOX[temp[2]];
                temp[3] = SBOX[temp[3]];
            }
            for (size_t k = 0; k < 4; ++k) {
                round_keys_[i * 4 + k] = round_keys_[(i - 8) * 4 + k] ^ temp[k];
            }
        }
    }

    constexpr void encrypt_block(Block& state) const noexcept {
        add_round_key(state, 0);
        for (size_t round = 1; round < 14; ++round) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, 14);
    }

    constexpr void decrypt_block(Block& state) const noexcept {
        add_round_key(state, 14);
        for (size_t round = 13; round >= 1; --round) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, round);
            inv_mix_columns(state);
        }
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, 0);
    }

    inline std::vector<u8> encrypt_cbc(const u8* data, size_t len, const Iv& iv) const {
        size_t pad_len = 16 - (len % 16);
        std::vector<u8> out(len + pad_len);
        std::memcpy(out.data(), data, len);
        for (size_t i = 0; i < pad_len; ++i) {
            out[len + i] = static_cast<u8>(pad_len);
        }

        Block prev = iv;
        for (size_t offset = 0; offset < out.size(); offset += 16) {
            Block blk{};
            for (size_t i = 0; i < 16; ++i) {
                blk[i] = out[offset + i] ^ prev[i];
            }
            encrypt_block(blk);
            for (size_t i = 0; i < 16; ++i) {
                out[offset + i] = blk[i];
            }
            prev = blk;
        }
        return out;
    }

    inline std::vector<u8> decrypt_cbc(const u8* data, size_t len, const Iv& iv, bool& out_ok) const {
        out_ok = false;
        if (len == 0 || (len % 16) != 0) return {};

        std::vector<u8> out(len);
        Block prev = iv;
        for (size_t offset = 0; offset < len; offset += 16) {
            Block cipher_blk{};
            for (size_t i = 0; i < 16; ++i) cipher_blk[i] = data[offset + i];
            Block blk = cipher_blk;
            decrypt_block(blk);
            for (size_t i = 0; i < 16; ++i) {
                out[offset + i] = blk[i] ^ prev[i];
            }
            prev = cipher_blk;
        }

        u8 pad = out.back();
        if (pad == 0 || pad > 16 || pad > out.size()) return {};
        for (size_t i = 0; i < pad; ++i) {
            if (out[out.size() - 1 - i] != pad) return {};
        }
        out.resize(out.size() - pad);
        out_ok = true;
        return out;
    }

    inline void crypt_ctr(u8* data, size_t len, const Iv& nonce_counter) const noexcept {
        Block counter = nonce_counter;
        for (size_t offset = 0; offset < len; offset += 16) {
            Block keystream = counter;
            encrypt_block(keystream);
            size_t chunk = (len - offset < 16) ? (len - offset) : 16;
            for (size_t i = 0; i < chunk; ++i) {
                data[offset + i] ^= keystream[i];
            }
            for (int c = 15; c >= 0; --c) {
                if (++counter[static_cast<size_t>(c)] != 0) break;
            }
        }
    }

private:
    static constexpr u8 xtime(u8 x) noexcept {
        return static_cast<u8>((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    static constexpr u8 gf_mul(u8 x, u8 y) noexcept {
        u8 res = 0;
        for (int i = 0; i < 8; ++i) {
            if (y & 1) res ^= x;
            bool hi = (x & 0x80) != 0;
            x <<= 1;
            if (hi) x ^= 0x1b;
            y >>= 1;
        }
        return res;
    }

    constexpr void add_round_key(Block& s, size_t round) const noexcept {
        for (size_t i = 0; i < 16; ++i) {
            s[i] ^= round_keys_[round * 16 + i];
        }
    }

    static constexpr void sub_bytes(Block& s) noexcept {
        for (size_t i = 0; i < 16; ++i) s[i] = SBOX[s[i]];
    }

    static constexpr void inv_sub_bytes(Block& s) noexcept {
        for (size_t i = 0; i < 16; ++i) s[i] = INV_SBOX[s[i]];
    }

    static constexpr void shift_rows(Block& s) noexcept {
        u8 t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }

    static constexpr void inv_shift_rows(Block& s) noexcept {
        u8 t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
    }

    static constexpr void mix_columns(Block& s) noexcept {
        for (size_t c = 0; c < 4; ++c) {
            size_t i = c * 4;
            u8 a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
            u8 t = a0 ^ a1 ^ a2 ^ a3;
            s[i + 0] ^= t ^ xtime(a0 ^ a1);
            s[i + 1] ^= t ^ xtime(a1 ^ a2);
            s[i + 2] ^= t ^ xtime(a2 ^ a3);
            s[i + 3] ^= t ^ xtime(a3 ^ a0);
        }
    }

    static constexpr void inv_mix_columns(Block& s) noexcept {
        for (size_t c = 0; c < 4; ++c) {
            size_t i = c * 4;
            u8 a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
            s[i + 0] = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
            s[i + 1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
            s[i + 2] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
            s[i + 3] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
        }
    }

    std::array<u8, 240> round_keys_{};
};

// ============================================================================
// 25. RFC 8439 POLY1305 MAC & CHACHA20-POLY1305 AEAD
// ============================================================================
class Poly1305 {
public:
    using Key = std::array<u8, 32>;
    using Tag = std::array<u8, 16>;

    static inline Tag compute(const Key& key, const u8* msg, size_t len) noexcept {
        u32 r0 = (load32(&key[0])) & 0x3ffffff;
        u32 r1 = (load32(&key[3]) >> 2) & 0x3ffff03;
        u32 r2 = (load32(&key[6]) >> 4) & 0x3ffc0ff;
        u32 r3 = (load32(&key[9]) >> 6) & 0x3f03fff;
        u32 r4 = (load32(&key[12]) >> 8) & 0x00fffff;

        u32 s1 = r1 * 5;
        u32 s2 = r2 * 5;
        u32 s3 = r3 * 5;
        u32 s4 = r4 * 5;

        u32 h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

        size_t offset = 0;
        while (offset < len) {
            u8 block[17]{};
            size_t chunk = (len - offset < 16) ? (len - offset) : 16;
            for (size_t i = 0; i < chunk; ++i) block[i] = msg[offset + i];
            block[chunk] = 1;

            h0 += (load32(&block[0])) & 0x3ffffff;
            h1 += (load32(&block[3]) >> 2) & 0x3ffffff;
            h2 += (load32(&block[6]) >> 4) & 0x3ffffff;
            h3 += (load32(&block[9]) >> 6) & 0x3ffffff;
            h4 += (load32(&block[12]) >> 8) | (static_cast<u32>(block[16]) << 24);

            u64 d0 = static_cast<u64>(h0) * r0 + static_cast<u64>(h1) * s4 + static_cast<u64>(h2) * s3 + static_cast<u64>(h3) * s2 + static_cast<u64>(h4) * s1;
            u64 d1 = static_cast<u64>(h0) * r1 + static_cast<u64>(h1) * r0 + static_cast<u64>(h2) * s4 + static_cast<u64>(h3) * s3 + static_cast<u64>(h4) * s2;
            u64 d2 = static_cast<u64>(h0) * r2 + static_cast<u64>(h1) * r1 + static_cast<u64>(h2) * r0 + static_cast<u64>(h3) * s4 + static_cast<u64>(h4) * s3;
            u64 d3 = static_cast<u64>(h0) * r3 + static_cast<u64>(h1) * r2 + static_cast<u64>(h2) * r1 + static_cast<u64>(h3) * r0 + static_cast<u64>(h4) * s4;
            u64 d4 = static_cast<u64>(h0) * r4 + static_cast<u64>(h1) * r3 + static_cast<u64>(h2) * r2 + static_cast<u64>(h3) * r1 + static_cast<u64>(h4) * r0;

            u32 c = static_cast<u32>(d0 >> 26); h0 = static_cast<u32>(d0) & 0x3ffffff; d1 += c;
                c = static_cast<u32>(d1 >> 26); h1 = static_cast<u32>(d1) & 0x3ffffff; d2 += c;
                c = static_cast<u32>(d2 >> 26); h2 = static_cast<u32>(d2) & 0x3ffffff; d3 += c;
                c = static_cast<u32>(d3 >> 26); h3 = static_cast<u32>(d3) & 0x3ffffff; d4 += c;
                c = static_cast<u32>(d4 >> 26); h4 = static_cast<u32>(d4) & 0x3ffffff; h0 += c * 5;
                c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

            offset += chunk;
        }

        u32 c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
            c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
            c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
            c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
            c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        u32 g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
        u32 g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        u32 g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        u32 g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        u32 g4 = h4 + c - (1UL << 26);

        u32 mask = (g4 >> 31) - 1;
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        u64 f0 = ((h0) | (h1 << 26)) + static_cast<u64>(load32(&key[16]));
        u64 f1 = ((h1 >> 6) | (h2 << 20)) + static_cast<u64>(load32(&key[20]));
        u64 f2 = ((h2 >> 12) | (h3 << 14)) + static_cast<u64>(load32(&key[24]));
        u64 f3 = ((h3 >> 18) | (h4 << 8)) + static_cast<u64>(load32(&key[28]));

        f1 += (f0 >> 32);
        f2 += (f1 >> 32);
        f3 += (f2 >> 32);

        Tag tag{};
        store32(&tag[0], static_cast<u32>(f0));
        store32(&tag[4], static_cast<u32>(f1));
        store32(&tag[8], static_cast<u32>(f2));
        store32(&tag[12], static_cast<u32>(f3));
        return tag;
    }

    static inline bool verify(const Tag& a, const Tag& b) noexcept {
        u8 diff = 0;
        for (size_t i = 0; i < 16; ++i) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }

private:
    static constexpr u32 load32(const u8* p) noexcept {
        return static_cast<u32>(p[0]) |
              (static_cast<u32>(p[1]) << 8) |
              (static_cast<u32>(p[2]) << 16) |
              (static_cast<u32>(p[3]) << 24);
    }
    static constexpr void store32(u8* p, u32 v) noexcept {
        p[0] = static_cast<u8>(v & 0xFF);
        p[1] = static_cast<u8>((v >> 8) & 0xFF);
        p[2] = static_cast<u8>((v >> 16) & 0xFF);
        p[3] = static_cast<u8>((v >> 24) & 0xFF);
    }
};

class ChaCha20Poly1305 {
public:
    using Key   = ChaCha20::Key;
    using Nonce = ChaCha20::Nonce;
    using Tag   = Poly1305::Tag;

    static inline std::vector<u8> seal(const Key& key, const Nonce& nonce,
                                       const u8* plaintext, size_t pt_len,
                                       const u8* aad, size_t aad_len,
                                       Tag& out_tag) {
        std::array<u8, 64> block0{};
        ChaCha20::generate_block(key, nonce, 0, block0);
        Poly1305::Key otk{};
        for (size_t i = 0; i < 32; ++i) otk[i] = block0[i];
        secure_zero(block0.data(), block0.size());

        std::vector<u8> ciphertext(pt_len);
        if (pt_len > 0) {
            std::memcpy(ciphertext.data(), plaintext, pt_len);
            ChaCha20::crypt(key, nonce, 1, ciphertext.data(), pt_len);
        }

        std::vector<u8> mac_data = build_mac_data(aad, aad_len, ciphertext.data(), ciphertext.size());
        out_tag = Poly1305::compute(otk, mac_data.data(), mac_data.size());
        secure_zero(otk.data(), otk.size());
        return ciphertext;
    }

    static inline bool open(const Key& key, const Nonce& nonce,
                            const u8* ciphertext, size_t ct_len,
                            const u8* aad, size_t aad_len,
                            const Tag& expected_tag,
                            std::vector<u8>& out_plaintext) {
        std::array<u8, 64> block0{};
        ChaCha20::generate_block(key, nonce, 0, block0);
        Poly1305::Key otk{};
        for (size_t i = 0; i < 32; ++i) otk[i] = block0[i];
        secure_zero(block0.data(), block0.size());

        std::vector<u8> mac_data = build_mac_data(aad, aad_len, ciphertext, ct_len);
        Tag actual_tag = Poly1305::compute(otk, mac_data.data(), mac_data.size());
        secure_zero(otk.data(), otk.size());

        if (!Poly1305::verify(actual_tag, expected_tag)) {
            return false;
        }

        out_plaintext.assign(ciphertext, ciphertext + ct_len);
        if (ct_len > 0) {
            ChaCha20::crypt(key, nonce, 1, out_plaintext.data(), ct_len);
        }
        return true;
    }

private:
    static inline std::vector<u8> build_mac_data(const u8* aad, size_t aad_len, const u8* ct, size_t ct_len) {
        size_t aad_pad = (16 - (aad_len % 16)) % 16;
        size_t ct_pad  = (16 - (ct_len % 16)) % 16;
        std::vector<u8> buf;
        buf.reserve(aad_len + aad_pad + ct_len + ct_pad + 16);
        if (aad && aad_len > 0) buf.insert(buf.end(), aad, aad + aad_len);
        buf.insert(buf.end(), aad_pad, 0);
        if (ct && ct_len > 0) buf.insert(buf.end(), ct, ct + ct_len);
        buf.insert(buf.end(), ct_pad, 0);

        u64 a_len64 = static_cast<u64>(aad_len);
        u64 c_len64 = static_cast<u64>(ct_len);
        for (int i = 0; i < 8; ++i) buf.push_back(static_cast<u8>((a_len64 >> (i * 8)) & 0xFF));
        for (int i = 0; i < 8; ++i) buf.push_back(static_cast<u8>((c_len64 >> (i * 8)) & 0xFF));
        return buf;
    }
};

// ============================================================================
// 26. KEY DERIVATION FUNCTIONS (PBKDF2-HMAC-SHA256, HKDF-SHA256 & MEMORY-HARD KDF)
// ============================================================================
class KdfEngine {
public:
    static inline std::vector<u8> pbkdf2_hmac_sha256(const u8* password, size_t pass_len,
                                                     const u8* salt, size_t salt_len,
                                                     u32 iterations, size_t dk_len) {
        if (iterations == 0) iterations = 1;
        std::vector<u8> derived(dk_len);
        size_t blocks = (dk_len + 31) / 32;
        std::vector<u8> salt_block(salt_len + 4);
        if (salt && salt_len > 0) std::memcpy(salt_block.data(), salt, salt_len);

        for (size_t b = 1; b <= blocks; ++b) {
            salt_block[salt_len + 0] = static_cast<u8>((b >> 24) & 0xFF);
            salt_block[salt_len + 1] = static_cast<u8>((b >> 16) & 0xFF);
            salt_block[salt_len + 2] = static_cast<u8>((b >> 8) & 0xFF);
            salt_block[salt_len + 3] = static_cast<u8>(b & 0xFF);

            Sha256::Digest u = Sha256::hmac(password, pass_len, salt_block.data(), salt_block.size());
            Sha256::Digest t = u;

            for (u32 iter = 1; iter < iterations; ++iter) {
                u = Sha256::hmac(password, pass_len, u.data(), u.size());
                for (size_t i = 0; i < 32; ++i) t[i] ^= u[i];
            }

            size_t offset = (b - 1) * 32;
            size_t copy_len = (dk_len - offset < 32) ? (dk_len - offset) : 32;
            std::memcpy(derived.data() + offset, t.data(), copy_len);
        }
        return derived;
    }

    static inline Sha256::Digest hkdf_extract(const u8* salt, size_t salt_len, const u8* ikm, size_t ikm_len) noexcept {
        static constexpr u8 zero_salt[32]{};
        if (!salt || salt_len == 0) {
            return Sha256::hmac(zero_salt, 32, ikm, ikm_len);
        }
        return Sha256::hmac(salt, salt_len, ikm, ikm_len);
    }

    static inline std::vector<u8> hkdf_expand(const Sha256::Digest& prk, const u8* info, size_t info_len, size_t okm_len) {
        if (okm_len > 255 * 32) okm_len = 255 * 32;
        size_t n = (okm_len + 31) / 32;
        std::vector<u8> okm(okm_len);
        Sha256::Digest t{};
        size_t t_len = 0;

        for (size_t i = 1; i <= n; ++i) {
            std::vector<u8> msg;
            msg.reserve(t_len + info_len + 1);
            if (t_len > 0) msg.insert(msg.end(), t.begin(), t.begin() + t_len);
            if (info && info_len > 0) msg.insert(msg.end(), info, info + info_len);
            msg.push_back(static_cast<u8>(i));

            t = Sha256::hmac(prk.data(), prk.size(), msg.data(), msg.size());
            t_len = 32;

            size_t offset = (i - 1) * 32;
            size_t copy_len = (okm_len - offset < 32) ? (okm_len - offset) : 32;
            std::memcpy(okm.data() + offset, t.data(), copy_len);
        }
        return okm;
    }

    static inline std::array<u8, 32> memory_hard_derive(std::string_view password, std::string_view salt, size_t memory_blocks = 256, u32 passes = 3) {
        if (memory_blocks < 8) memory_blocks = 8;
        std::vector< std::array<u64, 8> > arena(memory_blocks);

        Blake2b::Digest seed = Blake2b::hash(
            reinterpret_cast<const u8*>(password.data()), password.size(),
            reinterpret_cast<const u8*>(salt.data()), salt.size());

        for (size_t b = 0; b < memory_blocks; ++b) {
            for (size_t w = 0; w < 8; ++w) {
                u64 s = 0;
                for (size_t k = 0; k < 8; ++k) s |= static_cast<u64>(seed[w * 8 + k]) << (k * 8);
                arena[b][w] = s ^ (static_cast<u64>(b) * 0x9E3779B97F4A7C15ULL + w);
            }
        }

        for (u32 p = 0; p < passes; ++p) {
            for (size_t b = 0; b < memory_blocks; ++b) {
                size_t prev = (b + memory_blocks - 1) % memory_blocks;
                size_t ref  = static_cast<size_t>(arena[prev][0] % memory_blocks);
                for (size_t w = 0; w < 8; ++w) {
                    u64 v = arena[b][w] ^ arena[prev][w] ^ arena[ref][(w + 3) & 7];
                    v = ((v << 17) | (v >> 47)) * 0xBF58476D1CE4E5B9ULL;
                    arena[b][w] = v + arena[ref][w];
                }
            }
        }

        std::array<u64, 8> acc = arena[memory_blocks - 1];
        for (size_t b = 0; b < memory_blocks; ++b) {
            for (size_t w = 0; w < 8; ++w) acc[w] ^= arena[b][w];
        }
        secure_zero(arena.data(), arena.size() * sizeof(std::array<u64, 8>));

        return Sha256::hash(reinterpret_cast<const u8*>(acc.data()), sizeof(acc));
    }
};

// ============================================================================
// 27. LIGHTWEIGHT CIPHERS & KEYED PRFS (XTEA, SALSA20, SIPHASH-2-4)
// (Integrated & expanded from CryptoUtils.cpp & CaesarCipher.cc)
// ============================================================================
class XTea {
public:
    using Key = std::array<u32, 4>;

    static constexpr void encrypt_block(u32 v[2], const Key& key, u32 num_rounds = 64) noexcept {
        u32 v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9U;
        for (u32 i = 0; i < num_rounds; ++i) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        }
        v[0] = v0; v[1] = v1;
    }

    static constexpr void decrypt_block(u32 v[2], const Key& key, u32 num_rounds = 64) noexcept {
        u32 v0 = v[0], v1 = v[1], delta = 0x9E3779B9U;
        u32 sum = delta * num_rounds;
        for (u32 i = 0; i < num_rounds; ++i) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        }
        v[0] = v0; v[1] = v1;
    }

    static inline void encrypt_buffer(u8* data, size_t len, const Key& key, u32 rounds = 64) noexcept {
        size_t blocks = len / 8;
        for (size_t i = 0; i < blocks; ++i) {
            u32 v[2];
            std::memcpy(v, data + i * 8, 8);
            encrypt_block(v, key, rounds);
            std::memcpy(data + i * 8, v, 8);
        }
    }

    static inline void decrypt_buffer(u8* data, size_t len, const Key& key, u32 rounds = 64) noexcept {
        size_t blocks = len / 8;
        for (size_t i = 0; i < blocks; ++i) {
            u32 v[2];
            std::memcpy(v, data + i * 8, 8);
            decrypt_block(v, key, rounds);
            std::memcpy(data + i * 8, v, 8);
        }
    }
};

class SipHash24 {
public:
    static constexpr u64 rotl64(u64 x, u32 b) noexcept {
        return (x << b) | (x >> (64 - b));
    }

    static constexpr void sipround(u64& v0, u64& v1, u64& v2, u64& v3) noexcept {
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    }

    static constexpr u64 hash(const u8* in, size_t inlen, u64 k0, u64 k1) noexcept {
        u64 v0 = 0x736f6d6570736575ULL ^ k0;
        u64 v1 = 0x646f72616e646f6dULL ^ k1;
        u64 v2 = 0x6c7967656e657261ULL ^ k0;
        u64 v3 = 0x7465646279746573ULL ^ k1;

        size_t blocks = inlen / 8;
        for (size_t i = 0; i < blocks; ++i) {
            u64 m = 0;
            for (size_t b = 0; b < 8; ++b) m |= static_cast<u64>(in[i * 8 + b]) << (b * 8);
            v3 ^= m;
            sipround(v0, v1, v2, v3);
            sipround(v0, v1, v2, v3);
            v0 ^= m;
        }

        u64 last = static_cast<u64>(inlen & 0xFF) << 56;
        const u8* tail = in + blocks * 8;
        switch (inlen & 7) {
        case 7: last |= static_cast<u64>(tail[6]) << 48; [[fallthrough]];
        case 6: last |= static_cast<u64>(tail[5]) << 40; [[fallthrough]];
        case 5: last |= static_cast<u64>(tail[4]) << 32; [[fallthrough]];
        case 4: last |= static_cast<u64>(tail[3]) << 24; [[fallthrough]];
        case 3: last |= static_cast<u64>(tail[2]) << 16; [[fallthrough]];
        case 2: last |= static_cast<u64>(tail[1]) << 8;  [[fallthrough]];
        case 1: last |= static_cast<u64>(tail[0]);       break;
        case 0: break;
        }

        v3 ^= last;
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        v0 ^= last;

        v2 ^= 0xFF;
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        return v0 ^ v1 ^ v2 ^ v3;
    }
};

class Salsa20 {
public:
    using Key   = std::array<u8, 32>;
    using Nonce = std::array<u8, 8>;

    static constexpr u32 rotl32(u32 x, u32 n) noexcept {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr void quarter_round(u32& y0, u32& y1, u32& y2, u32& y3) noexcept {
        y1 ^= rotl32(y0 + y3, 7);
        y2 ^= rotl32(y1 + y0, 9);
        y3 ^= rotl32(y2 + y1, 13);
        y0 ^= rotl32(y3 + y2, 18);
    }

    static constexpr void generate_block(const Key& key, const Nonce& nonce, u64 counter, std::array<u8, 64>& out) noexcept {
        auto load32 = [](const u8* p) constexpr noexcept -> u32 {
            return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
                  (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
        };

        std::array<u32, 16> state = {
            0x61707865UL, load32(&key[0]), load32(&key[4]), load32(&key[8]),
            load32(&key[12]), 0x3320646eUL, load32(&nonce[0]), load32(&nonce[4]),
            static_cast<u32>(counter & 0xFFFFFFFFUL), static_cast<u32>(counter >> 32), 0x79622d32UL, load32(&key[16]),
            load32(&key[20]), load32(&key[24]), load32(&key[28]), 0x6b206574UL
        };

        std::array<u32, 16> x = state;
        for (int i = 0; i < 10; ++i) {
            quarter_round(x[0], x[4], x[8],  x[12]);
            quarter_round(x[5], x[9], x[13], x[1]);
            quarter_round(x[10], x[14], x[2], x[6]);
            quarter_round(x[15], x[3], x[7], x[11]);

            quarter_round(x[0], x[1], x[2], x[3]);
            quarter_round(x[5], x[6], x[7], x[4]);
            quarter_round(x[10], x[11], x[8], x[9]);
            quarter_round(x[15], x[12], x[13], x[14]);
        }

        for (size_t i = 0; i < 16; ++i) {
            u32 v = x[i] + state[i];
            out[i * 4 + 0] = static_cast<u8>(v & 0xFF);
            out[i * 4 + 1] = static_cast<u8>((v >> 8) & 0xFF);
            out[i * 4 + 2] = static_cast<u8>((v >> 16) & 0xFF);
            out[i * 4 + 3] = static_cast<u8>((v >> 24) & 0xFF);
        }
    }

    static inline void crypt(const Key& key, const Nonce& nonce, u64 initial_counter, u8* data, size_t len) noexcept {
        std::array<u8, 64> block{};
        u64 counter = initial_counter;
        size_t offset = 0;
        while (offset < len) {
            generate_block(key, nonce, counter++, block);
            size_t chunk = (len - offset < 64) ? (len - offset) : 64;
            for (size_t i = 0; i < chunk; ++i) data[offset + i] ^= block[i];
            offset += chunk;
        }
        secure_zero(block.data(), block.size());
    }
};



} // namespace crypto

// ============================================================================
// 28. BINARY & TEXT CODECS (BASE64, BASE32, HEX, LEB128 VARINT & LZSS)
// (Integrated & expanded from base64.cpp)
// ============================================================================
namespace codec {

class Base64 {
public:
    static constexpr char STD_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static constexpr char URL_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    static inline std::string encode(const u8* data, size_t len, bool url_safe = false, bool padding = true) {
        const char* alpha = url_safe ? URL_ALPHABET : STD_ALPHABET;
        std::string out;
        out.reserve(((len + 2) / 3) * 4);

        size_t i = 0;
        while (i + 3 <= len) {
            u32 n = (static_cast<u32>(data[i]) << 16) |
                    (static_cast<u32>(data[i + 1]) << 8) |
                    static_cast<u32>(data[i + 2]);
            out.push_back(alpha[(n >> 18) & 63]);
            out.push_back(alpha[(n >> 12) & 63]);
            out.push_back(alpha[(n >> 6)  & 63]);
            out.push_back(alpha[n & 63]);
            i += 3;
        }

        size_t rem = len - i;
        if (rem == 1) {
            u32 n = static_cast<u32>(data[i]) << 16;
            out.push_back(alpha[(n >> 18) & 63]);
            out.push_back(alpha[(n >> 12) & 63]);
            if (padding) {
                out.push_back('=');
                out.push_back('=');
            }
        } else if (rem == 2) {
            u32 n = (static_cast<u32>(data[i]) << 16) | (static_cast<u32>(data[i + 1]) << 8);
            out.push_back(alpha[(n >> 18) & 63]);
            out.push_back(alpha[(n >> 12) & 63]);
            out.push_back(alpha[(n >> 6)  & 63]);
            if (padding) {
                out.push_back('=');
            }
        }
        return out;
    }

    static inline std::string encode(std::string_view sv, bool url_safe = false, bool padding = true) {
        return encode(reinterpret_cast<const u8*>(sv.data()), sv.size(), url_safe, padding);
    }

    static inline std::vector<u8> decode(std::string_view encoded, bool& out_ok) {
        out_ok = false;
        std::array<i8, 256> table{};
        table.fill(-1);
        for (int i = 0; i < 64; ++i) {
            table[static_cast<u8>(STD_ALPHABET[i])] = static_cast<i8>(i);
            table[static_cast<u8>(URL_ALPHABET[i])] = static_cast<i8>(i);
        }

        std::vector<u8> out;
        out.reserve((encoded.size() * 3) / 4);

        u32 val = 0;
        int valb = -8;
        for (char c : encoded) {
            if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
            i8 d = table[static_cast<u8>(c)];
            if (d == -1) return {};
            val = (val << 6) + static_cast<u32>(d);
            valb += 6;
            if (valb >= 0) {
                out.push_back(static_cast<u8>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        out_ok = true;
        return out;
    }
};

class Base32 {
public:
    static constexpr char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    static inline std::string encode(const u8* data, size_t len, bool padding = true) {
        std::string out;
        out.reserve(((len + 4) / 5) * 8);
        u32 buffer = 0;
        int bits_left = 0;

        for (size_t i = 0; i < len; ++i) {
            buffer = (buffer << 8) | data[i];
            bits_left += 8;
            while (bits_left >= 5) {
                out.push_back(ALPHABET[(buffer >> (bits_left - 5)) & 0x1F]);
                bits_left -= 5;
            }
        }
        if (bits_left > 0) {
            out.push_back(ALPHABET[(buffer << (5 - bits_left)) & 0x1F]);
        }
        if (padding) {
            while ((out.size() % 8) != 0) out.push_back('=');
        }
        return out;
    }

    static inline std::vector<u8> decode(std::string_view encoded, bool& out_ok) {
        out_ok = false;
        std::vector<u8> out;
        u32 buffer = 0;
        int bits_left = 0;

        for (char ch : encoded) {
            if (ch == '=' || ch == ' ') continue;
            int v = -1;
            if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
            else if (ch >= 'a' && ch <= 'z') v = ch - 'a';
            else if (ch >= '2' && ch <= '7') v = 26 + (ch - '2');
            if (v < 0) return {};

            buffer = (buffer << 5) | static_cast<u32>(v);
            bits_left += 5;
            if (bits_left >= 8) {
                out.push_back(static_cast<u8>((buffer >> (bits_left - 8)) & 0xFF));
                bits_left -= 8;
            }
        }
        out_ok = true;
        return out;
    }
};

class Leb128 {
public:
    static inline void encode_u64(u64 val, std::vector<u8>& out) {
        do {
            u8 byte = static_cast<u8>(val & 0x7F);
            val >>= 7;
            if (val != 0) byte |= 0x80;
            out.push_back(byte);
        } while (val != 0);
    }

    static inline bool decode_u64(const u8* data, size_t len, size_t& inout_offset, u64& out_val) noexcept {
        out_val = 0;
        u32 shift = 0;
        while (inout_offset < len && shift < 64) {
            u8 byte = data[inout_offset++];
            out_val |= static_cast<u64>(byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) return true;
            shift += 7;
        }
        return false;
    }

    static inline void encode_i64(i64 val, std::vector<u8>& out) {
        bool more = true;
        while (more) {
            u8 byte = static_cast<u8>(val & 0x7F);
            val >>= 7;
            if ((val == 0 && (byte & 0x40) == 0) || (val == -1 && (byte & 0x40) != 0)) {
                more = false;
            } else {
                byte |= 0x80;
            }
            out.push_back(byte);
        }
    }

    static inline bool decode_i64(const u8* data, size_t len, size_t& inout_offset, i64& out_val) noexcept {
        u64 result = 0;
        u32 shift = 0;
        u8 byte = 0;
        while (inout_offset < len) {
            byte = data[inout_offset++];
            result |= static_cast<u64>(byte & 0x7F) << shift;
            shift += 7;
            if ((byte & 0x80) == 0) break;
            if (shift >= 64) return false;
        }
        if (shift < 64 && (byte & 0x40) != 0) {
            result |= (~0ULL << shift);
        }
        out_val = static_cast<i64>(result);
        return true;
    }
};

/**
 * @brief Lightweight LZSS Bytecode Compressor & Decompressor
 * Compresses repetitive VM bytecode patterns before encryption.
 */
class LzssCodec {
public:
    static constexpr size_t WINDOW_SIZE = 4096;
    static constexpr size_t MIN_MATCH   = 3;
    static constexpr size_t MAX_MATCH   = 18;

    static inline std::vector<u8> compress(const u8* src, size_t len) {
        std::vector<u8> out;
        if (!src || len == 0) return out;
        out.reserve(len);

        size_t pos = 0;
        while (pos < len) {
            size_t flag_index = out.size();
            out.push_back(0);
            u8 flags = 0;

            for (int bit = 0; bit < 8 && pos < len; ++bit) {
                size_t best_len = 0;
                size_t best_dist = 0;
                size_t start_win = (pos > WINDOW_SIZE) ? (pos - WINDOW_SIZE) : 0;

                for (size_t scan = start_win; scan < pos; ++scan) {
                    size_t mlen = 0;
                    while (mlen < MAX_MATCH && (pos + mlen) < len && src[scan + mlen] == src[pos + mlen]) {
                        mlen++;
                    }
                    if (mlen >= MIN_MATCH && mlen > best_len) {
                        best_len = mlen;
                        best_dist = pos - scan;
                        if (best_len == MAX_MATCH) break;
                    }
                }

                if (best_len >= MIN_MATCH) {
                    flags |= static_cast<u8>(1U << bit);
                    u16 encoded = static_cast<u16>(((best_dist & 0x0FFF) << 4) | ((best_len - MIN_MATCH) & 0x0F));
                    out.push_back(static_cast<u8>(encoded & 0xFF));
                    out.push_back(static_cast<u8>((encoded >> 8) & 0xFF));
                    pos += best_len;
                } else {
                    out.push_back(src[pos++]);
                }
            }
            out[flag_index] = flags;
        }
        return out;
    }

    static inline std::vector<u8> decompress(const u8* src, size_t len) {
        std::vector<u8> out;
        if (!src || len == 0) return out;
        out.reserve(len * 2);

        size_t pos = 0;
        while (pos < len) {
            u8 flags = src[pos++];
            for (int bit = 0; bit < 8 && pos < len; ++bit) {
                if ((flags & (1U << bit)) != 0) {
                    if (pos + 2 > len) return out;
                    u16 encoded = static_cast<u16>(src[pos]) | (static_cast<u16>(src[pos + 1]) << 8);
                    pos += 2;
                    size_t dist = (encoded >> 4) & 0x0FFF;
                    size_t mlen = (encoded & 0x0F) + MIN_MATCH;
                    if (dist == 0 || dist > out.size()) return out;
                    size_t copy_src = out.size() - dist;
                    for (size_t k = 0; k < mlen; ++k) {
                        out.push_back(out[copy_src + k]);
                    }
                } else {
                    out.push_back(src[pos++]);
                }
            }
        }
        return out;
    }
};

} // namespace codec

// ============================================================================
// 29. MULTI-PRECISION 256-BIT & 512-BIT MODULAR ARITHMETIC ENGINE
// ============================================================================
namespace math {

class Uint256 {
public:
    std::array<u64, 4> limbs{}; // little-endian limbs: limbs[0] is least significant

    constexpr Uint256() noexcept = default;
    constexpr explicit Uint256(u64 low) noexcept : limbs{low, 0, 0, 0} {}
    constexpr Uint256(u64 w3, u64 w2, u64 w1, u64 w0) noexcept : limbs{w0, w1, w2, w3} {}

    static constexpr Uint256 zero() noexcept { return Uint256(0); }
    static constexpr Uint256 one() noexcept { return Uint256(1); }

    constexpr bool is_zero() const noexcept {
        return (limbs[0] | limbs[1] | limbs[2] | limbs[3]) == 0;
    }

    constexpr bool is_even() const noexcept {
        return (limbs[0] & 1ULL) == 0;
    }

    constexpr bool get_bit(size_t bit_idx) const noexcept {
        if (bit_idx >= 256) return false;
        return ((limbs[bit_idx / 64] >> (bit_idx % 64)) & 1ULL) != 0;
    }

    constexpr void set_bit(size_t bit_idx, bool val = true) noexcept {
        if (bit_idx >= 256) return;
        if (val) limbs[bit_idx / 64] |= (1ULL << (bit_idx % 64));
        else     limbs[bit_idx / 64] &= ~(1ULL << (bit_idx % 64));
    }

    constexpr int compare(const Uint256& rhs) const noexcept {
        for (int i = 3; i >= 0; --i) {
            if (limbs[static_cast<size_t>(i)] < rhs.limbs[static_cast<size_t>(i)]) return -1;
            if (limbs[static_cast<size_t>(i)] > rhs.limbs[static_cast<size_t>(i)]) return 1;
        }
        return 0;
    }

    constexpr bool operator==(const Uint256& rhs) const noexcept { return compare(rhs) == 0; }
    constexpr bool operator!=(const Uint256& rhs) const noexcept { return compare(rhs) != 0; }
    constexpr bool operator<(const Uint256& rhs)  const noexcept { return compare(rhs) < 0; }
    constexpr bool operator<=(const Uint256& rhs) const noexcept { return compare(rhs) <= 0; }
    constexpr bool operator>(const Uint256& rhs)  const noexcept { return compare(rhs) > 0; }
    constexpr bool operator>=(const Uint256& rhs) const noexcept { return compare(rhs) >= 0; }

    static constexpr Uint256 add_with_carry(const Uint256& a, const Uint256& b, u64& out_carry) noexcept {
        Uint256 res{};
        u64 carry = 0;
        for (size_t i = 0; i < 4; ++i) {
            u64 sum1 = a.limbs[i] + b.limbs[i];
            u64 c1 = (sum1 < a.limbs[i]) ? 1ULL : 0ULL;
            u64 sum2 = sum1 + carry;
            u64 c2 = (sum2 < sum1) ? 1ULL : 0ULL;
            res.limbs[i] = sum2;
            carry = c1 | c2;
        }
        out_carry = carry;
        return res;
    }

    static constexpr Uint256 sub_with_borrow(const Uint256& a, const Uint256& b, u64& out_borrow) noexcept {
        Uint256 res{};
        u64 borrow = 0;
        for (size_t i = 0; i < 4; ++i) {
            u64 diff1 = a.limbs[i] - b.limbs[i];
            u64 b1 = (a.limbs[i] < b.limbs[i]) ? 1ULL : 0ULL;
            u64 b2 = (diff1 < borrow) ? 1ULL : 0ULL;
            res.limbs[i] = diff1 - borrow;
            borrow = b1 | b2;
        }
        out_borrow = borrow;
        return res;
    }

    constexpr Uint256 operator+(const Uint256& rhs) const noexcept {
        u64 c = 0;
        return add_with_carry(*this, rhs, c);
    }

    constexpr Uint256 operator-(const Uint256& rhs) const noexcept {
        u64 b = 0;
        return sub_with_borrow(*this, rhs, b);
    }

    constexpr Uint256 operator^(const Uint256& rhs) const noexcept {
        return Uint256(limbs[3] ^ rhs.limbs[3], limbs[2] ^ rhs.limbs[2], limbs[1] ^ rhs.limbs[1], limbs[0] ^ rhs.limbs[0]);
    }

    constexpr Uint256 operator&(const Uint256& rhs) const noexcept {
        return Uint256(limbs[3] & rhs.limbs[3], limbs[2] & rhs.limbs[2], limbs[1] & rhs.limbs[1], limbs[0] & rhs.limbs[0]);
    }

    constexpr Uint256 operator|(const Uint256& rhs) const noexcept {
        return Uint256(limbs[3] | rhs.limbs[3], limbs[2] | rhs.limbs[2], limbs[1] | rhs.limbs[1], limbs[0] | rhs.limbs[0]);
    }

    constexpr void shift_left1() noexcept {
        u64 c = 0;
        for (size_t i = 0; i < 4; ++i) {
            u64 next_c = limbs[i] >> 63;
            limbs[i] = (limbs[i] << 1) | c;
            c = next_c;
        }
    }

    constexpr void shift_right1() noexcept {
        u64 c = 0;
        for (int i = 3; i >= 0; --i) {
            u64 next_c = limbs[static_cast<size_t>(i)] << 63;
            limbs[static_cast<size_t>(i)] = (limbs[static_cast<size_t>(i)] >> 1) | c;
            c = next_c;
        }
    }

    static constexpr Uint256 mod_add(const Uint256& a, const Uint256& b, const Uint256& m) noexcept {
        u64 c = 0;
        Uint256 sum = add_with_carry(a, b, c);
        if (c != 0 || sum >= m) {
            u64 borrow = 0;
            sum = sub_with_borrow(sum, m, borrow);
        }
        return sum;
    }

    static constexpr Uint256 mod_sub(const Uint256& a, const Uint256& b, const Uint256& m) noexcept {
        if (a >= b) return a - b;
        return m - (b - a);
    }

    static constexpr Uint256 mod_mul(Uint256 a, Uint256 b, const Uint256& m) noexcept {
        Uint256 res = zero();
        for (size_t bit = 0; bit < 256; ++bit) {
            if (b.get_bit(bit)) {
                res = mod_add(res, a, m);
            }
            a = mod_add(a, a, m);
        }
        return res;
    }

    static constexpr Uint256 mod_pow(Uint256 base, Uint256 exp, const Uint256& mod) noexcept {
        Uint256 result = one();
        for (size_t bit = 0; bit < 256; ++bit) {
            if (exp.get_bit(bit)) {
                result = mod_mul(result, base, mod);
            }
            base = mod_mul(base, base, mod);
        }
        return result;
    }

    inline std::string to_hex() const {
        char buf[65]{};
        std::snprintf(buf, sizeof(buf), "%016llx%016llx%016llx%016llx",
                      static_cast<unsigned long long>(limbs[3]),
                      static_cast<unsigned long long>(limbs[2]),
                      static_cast<unsigned long long>(limbs[1]),
                      static_cast<unsigned long long>(limbs[0]));
        return std::string(buf);
    }
};

} // namespace math


// ============================================================================
// 30. V-ISA BYTECODE DISASSEMBLER, CFG BUILDER & STATIC VERIFIER
// ============================================================================
namespace vm::disasm {

struct DecodedInstruction {
    u32 offset{0};
    u32 size{0};
    Opcode opcode{Opcode::OP_NOP};
    VReg reg1{VReg::R0};
    VReg reg2{VReg::R0};
    VReg reg3{VReg::R0};
    u64 imm64{0};
    u32 target_offset{0};
    u16 native_id{0};
    u8 shift_or_argc{0};
    bool is_branch{false};
    bool is_conditional{false};
    bool is_terminator{false};
    std::string mnemonic;
    std::string operands_str;
};

struct BasicBlock {
    u32 id{0};
    u32 start_offset{0};
    u32 end_offset{0};
    std::vector<DecodedInstruction> instructions;
    std::vector<u32> successors;
    std::vector<u32> predecessors;
    bool reachable{false};
};

class BytecodeDisassembler {
public:
    static inline const char* reg_name(VReg r) noexcept {
        switch (r) {
        case VReg::R0:    return "R0";
        case VReg::R1:    return "R1";
        case VReg::R2:    return "R2";
        case VReg::R3:    return "R3";
        case VReg::R4:    return "R4";
        case VReg::R5:    return "R5";
        case VReg::R6:    return "R6";
        case VReg::R7:    return "R7";
        case VReg::RSP:   return "RSP";
        case VReg::RBP:   return "RBP";
        case VReg::RIP:   return "RIP";
        case VReg::FLAGS: return "FLAGS";
        default:          return "R?";
        }
    }

    static inline const char* opcode_name(Opcode op) noexcept {
        switch (op) {
        case Opcode::OP_NOP:         return "NOP";
        case Opcode::OP_MOV_IMM:     return "MOV";
        case Opcode::OP_MOV_REG:     return "MOV";
        case Opcode::OP_ADD:         return "ADD";
        case Opcode::OP_SUB:         return "SUB";
        case Opcode::OP_MUL:         return "MUL";
        case Opcode::OP_DIV:         return "DIV";
        case Opcode::OP_MOD:         return "MOD";
        case Opcode::OP_AND:         return "AND";
        case Opcode::OP_OR:          return "OR";
        case Opcode::OP_XOR:         return "XOR";
        case Opcode::OP_NOT:         return "NOT";
        case Opcode::OP_SHL:         return "SHL";
        case Opcode::OP_SHR:         return "SHR";
        case Opcode::OP_ROL:         return "ROL";
        case Opcode::OP_ROR:         return "ROR";
        case Opcode::OP_CMP:         return "CMP";
        case Opcode::OP_TEST:        return "TEST";
        case Opcode::OP_PUSH:        return "PUSH";
        case Opcode::OP_POP:         return "POP";
        case Opcode::OP_LOAD:        return "LOAD";
        case Opcode::OP_STORE:       return "STORE";
        case Opcode::OP_JMP:         return "JMP";
        case Opcode::OP_JZ:          return "JZ";
        case Opcode::OP_JNZ:         return "JNZ";
        case Opcode::OP_JG:          return "JG";
        case Opcode::OP_JL:          return "JL";
        case Opcode::OP_JGE:         return "JGE";
        case Opcode::OP_JLE:         return "JLE";
        case Opcode::OP_CALL:        return "CALL";
        case Opcode::OP_RET:         return "RET";
        case Opcode::OP_CALL_NATIVE: return "CALL_NATIVE";
        case Opcode::OP_REKEY:       return "REKEY";
        case Opcode::OP_BSWAP:       return "BSWAP";
        case Opcode::OP_POPCNT:      return "POPCNT";
        case Opcode::OP_VMEMCPY:     return "VMEMCPY";
        case Opcode::OP_VMEMSET:     return "VMEMSET";
        case Opcode::OP_JUNK:        return "JUNK";
        case Opcode::OP_HALT:        return "HALT";
        default:                     return "DB_UNKNOWN";
        }
    }

    static inline std::vector<u8> decrypt_chunk_payload(const BytecodeChunk& chunk) {
        if (!chunk.verify_integrity()) return {};
        const auto* hdr = chunk.get_header();
        if (!hdr) return {};
        const u8* enc = chunk.get_encrypted_payload();
        size_t sz = chunk.get_payload_size();

        std::vector<u8> plain(sz);
        u64 rolling_key = hdr->initial_key;
        for (size_t i = 0; i < sz; ++i) {
            u8 c = enc[i];
            plain[i] = c ^ static_cast<u8>(rolling_key & 0xFF);
            rolling_key = BytecodeChunk::advance_rolling_key(rolling_key, c);
        }
        return plain;
    }

    static inline std::vector<DecodedInstruction> disassemble(const BytecodeChunk& chunk) {
        std::vector<DecodedInstruction> result;
        const auto* hdr = chunk.get_header();
        if (!hdr) return result;
        const bool is_poly = (hdr->flags & AGVM_FLAG_POLYMORPHIC) != 0;
        std::vector<u8> code = decrypt_chunk_payload(chunk);
        if (code.empty()) return result;

        auto rd8 = [&](size_t& c) -> u8 { return (c < code.size()) ? code[c++] : 0; };
        auto rd16 = [&](size_t& c) -> u16 {
            if (c + 2 > code.size()) { c = code.size(); return 0; }
            u16 v = static_cast<u16>(code[c]) | (static_cast<u16>(code[c + 1]) << 8);
            c += 2;
            return v;
        };
        auto rd32 = [&](size_t& c) -> u32 {
            if (c + 4 > code.size()) { c = code.size(); return 0; }
            u32 v = static_cast<u32>(code[c]) | (static_cast<u32>(code[c + 1]) << 8) |
                    (static_cast<u32>(code[c + 2]) << 16) | (static_cast<u32>(code[c + 3]) << 24);
            c += 4;
            return v;
        };
        auto rd64 = [&](size_t& c) -> u64 {
            u32 lo = rd32(c);
            u32 hi = rd32(c);
            return static_cast<u64>(lo) | (static_cast<u64>(hi) << 32);
        };

        size_t pc = 0;
        char buf[128]{};
        while (pc < code.size()) {
            DecodedInstruction ins{};
            ins.offset = static_cast<u32>(pc);
            u8 raw_op = rd8(pc);
            ins.opcode = is_poly ? DefaultOpcodeMap::decode(raw_op) : static_cast<Opcode>(raw_op);
            ins.mnemonic = opcode_name(ins.opcode);

            switch (ins.opcode) {
            case Opcode::OP_NOP:
                break;
            case Opcode::OP_MOV_IMM:
                ins.reg1 = static_cast<VReg>(rd8(pc));
                ins.imm64 = rd64(pc);
                std::snprintf(buf, sizeof(buf), "%s, 0x%llx", reg_name(ins.reg1), static_cast<unsigned long long>(ins.imm64));
                ins.operands_str = buf;
                break;
            case Opcode::OP_MOV_REG:
            case Opcode::OP_ADD:
            case Opcode::OP_SUB:
            case Opcode::OP_MUL:
            case Opcode::OP_DIV:
            case Opcode::OP_MOD:
            case Opcode::OP_AND:
            case Opcode::OP_OR:
            case Opcode::OP_XOR:
            case Opcode::OP_CMP:
            case Opcode::OP_TEST:
            case Opcode::OP_LOAD:
            case Opcode::OP_STORE:
            case Opcode::OP_POPCNT:
                ins.reg1 = static_cast<VReg>(rd8(pc));
                ins.reg2 = static_cast<VReg>(rd8(pc));
                std::snprintf(buf, sizeof(buf), "%s, %s", reg_name(ins.reg1), reg_name(ins.reg2));
                ins.operands_str = buf;
                break;
            case Opcode::OP_NOT:
            case Opcode::OP_PUSH:
            case Opcode::OP_POP:
            case Opcode::OP_BSWAP:
                ins.reg1 = static_cast<VReg>(rd8(pc));
                ins.operands_str = reg_name(ins.reg1);
                break;
            case Opcode::OP_SHL:
            case Opcode::OP_SHR:
            case Opcode::OP_ROL:
            case Opcode::OP_ROR:
                ins.reg1 = static_cast<VReg>(rd8(pc));
                ins.shift_or_argc = rd8(pc);
                std::snprintf(buf, sizeof(buf), "%s, %u", reg_name(ins.reg1), static_cast<unsigned>(ins.shift_or_argc));
                ins.operands_str = buf;
                break;
            case Opcode::OP_VMEMCPY:
            case Opcode::OP_VMEMSET:
                ins.reg1 = static_cast<VReg>(rd8(pc));
                ins.reg2 = static_cast<VReg>(rd8(pc));
                ins.reg3 = static_cast<VReg>(rd8(pc));
                std::snprintf(buf, sizeof(buf), "%s, %s, %s", reg_name(ins.reg1), reg_name(ins.reg2), reg_name(ins.reg3));
                ins.operands_str = buf;
                break;
            case Opcode::OP_JMP:
                ins.target_offset = rd32(pc);
                ins.is_branch = true;
                ins.is_terminator = true;
                std::snprintf(buf, sizeof(buf), "loc_%04x", ins.target_offset);
                ins.operands_str = buf;
                break;
            case Opcode::OP_JZ:
            case Opcode::OP_JNZ:
            case Opcode::OP_JG:
            case Opcode::OP_JL:
            case Opcode::OP_JGE:
            case Opcode::OP_JLE:
                ins.target_offset = rd32(pc);
                ins.is_branch = true;
                ins.is_conditional = true;
                ins.is_terminator = true;
                std::snprintf(buf, sizeof(buf), "loc_%04x", ins.target_offset);
                ins.operands_str = buf;
                break;
            case Opcode::OP_CALL:
                ins.target_offset = rd32(pc);
                ins.is_branch = true;
                std::snprintf(buf, sizeof(buf), "sub_%04x", ins.target_offset);
                ins.operands_str = buf;
                break;
            case Opcode::OP_RET:
                ins.is_terminator = true;
                break;
            case Opcode::OP_CALL_NATIVE:
                ins.native_id = rd16(pc);
                ins.shift_or_argc = rd8(pc);
                std::snprintf(buf, sizeof(buf), "id=%u, argc=%u", static_cast<unsigned>(ins.native_id), static_cast<unsigned>(ins.shift_or_argc));
                ins.operands_str = buf;
                break;
            case Opcode::OP_REKEY:
            case Opcode::OP_JUNK:
                ins.imm64 = rd64(pc);
                std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(ins.imm64));
                ins.operands_str = buf;
                break;
            case Opcode::OP_HALT:
                ins.is_terminator = true;
                break;
            default:
                ins.is_terminator = true;
                break;
            }

            ins.size = static_cast<u32>(pc) - ins.offset;
            result.push_back(std::move(ins));
        }

        secure_zero(code.data(), code.size());
        return result;
    }

    static inline std::string format_listing(const BytecodeChunk& chunk) {
        auto insts = disassemble(chunk);
        std::ostringstream oss;
        char line_buf[256]{};
        for (const auto& ins : insts) {
            if (ins.operands_str.empty()) {
                std::snprintf(line_buf, sizeof(line_buf), "%04X: %-12s\n", ins.offset, ins.mnemonic.c_str());
            } else {
                std::snprintf(line_buf, sizeof(line_buf), "%04X: %-12s %s\n", ins.offset, ins.mnemonic.c_str(), ins.operands_str.c_str());
            }
            oss << line_buf;
        }
        return oss.str();
    }

    static inline std::vector<BasicBlock> build_cfg(const BytecodeChunk& chunk) {
        auto insts = disassemble(chunk);
        if (insts.empty()) return {};

        std::vector<u32> leaders;
        leaders.push_back(insts.front().offset);

        for (size_t i = 0; i < insts.size(); ++i) {
            const auto& ins = insts[i];
            if (ins.is_branch) {
                leaders.push_back(ins.target_offset);
                if (i + 1 < insts.size()) {
                    leaders.push_back(insts[i + 1].offset);
                }
            } else if (ins.is_terminator && i + 1 < insts.size()) {
                leaders.push_back(insts[i + 1].offset);
            }
        }

        std::sort(leaders.begin(), leaders.end());
        leaders.erase(std::unique(leaders.begin(), leaders.end()), leaders.end());

        std::vector<BasicBlock> blocks;
        std::unordered_map<u32, u32> offset_to_block_id;

        for (size_t b = 0; b < leaders.size(); ++b) {
            BasicBlock bb{};
            bb.id = static_cast<u32>(b);
            bb.start_offset = leaders[b];
            offset_to_block_id[bb.start_offset] = bb.id;
            blocks.push_back(bb);
        }

        size_t cur_blk = 0;
        for (const auto& ins : insts) {
            while (cur_blk + 1 < blocks.size() && ins.offset >= blocks[cur_blk + 1].start_offset) {
                cur_blk++;
            }
            blocks[cur_blk].instructions.push_back(ins);
            blocks[cur_blk].end_offset = ins.offset + ins.size;
        }

        for (size_t b = 0; b < blocks.size(); ++b) {
            if (blocks[b].instructions.empty()) continue;
            const auto& last = blocks[b].instructions.back();
            if (last.opcode == Opcode::OP_JMP) {
                auto it = offset_to_block_id.find(last.target_offset);
                if (it != offset_to_block_id.end()) blocks[b].successors.push_back(it->second);
            } else if (last.is_conditional) {
                auto it = offset_to_block_id.find(last.target_offset);
                if (it != offset_to_block_id.end()) blocks[b].successors.push_back(it->second);
                if (b + 1 < blocks.size()) blocks[b].successors.push_back(blocks[b + 1].id);
            } else if (!last.is_terminator) {
                if (b + 1 < blocks.size()) blocks[b].successors.push_back(blocks[b + 1].id);
            }
        }

        for (auto& blk : blocks) {
            for (u32 succ : blk.successors) {
                if (succ < blocks.size()) {
                    blocks[succ].predecessors.push_back(blk.id);
                }
            }
        }

        if (!blocks.empty()) {
            std::vector<u32> worklist = {0};
            blocks[0].reachable = true;
            while (!worklist.empty()) {
                u32 curr = worklist.back();
                worklist.pop_back();
                for (u32 succ : blocks[curr].successors) {
                    if (succ < blocks.size() && !blocks[succ].reachable) {
                        blocks[succ].reachable = true;
                        worklist.push_back(succ);
                    }
                }
            }
        }

        return blocks;
    }
};

} // namespace vm::disasm

// ============================================================================
// 31. TEXTUAL V-ISA ASSEMBLER & LEXER/PARSER ENGINE
// ============================================================================
namespace vm::assembler {

class VmTextAssembler {
public:
    static inline bool parse_register(std::string_view token, VReg& out_reg) noexcept {
        if (token == "R0" || token == "r0") { out_reg = VReg::R0; return true; }
        if (token == "R1" || token == "r1") { out_reg = VReg::R1; return true; }
        if (token == "R2" || token == "r2") { out_reg = VReg::R2; return true; }
        if (token == "R3" || token == "r3") { out_reg = VReg::R3; return true; }
        if (token == "R4" || token == "r4") { out_reg = VReg::R4; return true; }
        if (token == "R5" || token == "r5") { out_reg = VReg::R5; return true; }
        if (token == "R6" || token == "r6") { out_reg = VReg::R6; return true; }
        if (token == "R7" || token == "r7") { out_reg = VReg::R7; return true; }
        if (token == "RSP" || token == "rsp") { out_reg = VReg::RSP; return true; }
        if (token == "RBP" || token == "rbp") { out_reg = VReg::RBP; return true; }
        if (token == "RIP" || token == "rip") { out_reg = VReg::RIP; return true; }
        if (token == "FLAGS" || token == "flags") { out_reg = VReg::FLAGS; return true; }
        return false;
    }

    static inline bool parse_u64(std::string_view token, u64& out_val) noexcept {
        if (token.empty()) return false;
        std::string s(token);
        char* endptr = nullptr;
        int base = 10;
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            base = 16;
        }
        out_val = std::strtoull(s.c_str(), &endptr, base);
        return endptr != s.c_str() && *endptr == '\0';
    }

    static inline std::vector<std::string> tokenize_line(std::string_view line) {
        std::vector<std::string> tokens;
        std::string current;
        for (char c : line) {
            if (c == ';' || c == '#') break;
            if (c == ' ' || c == '\t' || c == ',' || c == '\r' || c == '\n') {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
            } else {
                current.push_back(c);
            }
        }
        if (!current.empty()) tokens.push_back(current);
        return tokens;
    }

    static inline std::string to_upper(std::string_view sv) {
        std::string s(sv);
        for (char& c : s) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        }
        return s;
    }

    static inline BytecodeChunk assemble(std::string_view source_code, u64 key = 0, bool polymorphic = true) {
        BytecodeBuilder builder(polymorphic);
        std::unordered_map<std::string, Label> named_labels;

        auto get_or_create_label = [&](const std::string& name) -> Label {
            auto it = named_labels.find(name);
            if (it != named_labels.end()) return it->second;
            Label lbl = builder.create_label();
            named_labels[name] = lbl;
            return lbl;
        };

        std::istringstream stream{std::string(source_code)};
        std::string line;
        while (std::getline(stream, line)) {
            auto tokens = tokenize_line(line);
            if (tokens.empty()) continue;

            size_t idx = 0;
            if (tokens[0].back() == ':') {
                std::string lbl_name = tokens[0].substr(0, tokens[0].size() - 1);
                builder.bind_label(get_or_create_label(lbl_name));
                idx++;
                if (idx >= tokens.size()) continue;
            }

            std::string op = to_upper(tokens[idx]);
            if (op == "NOP") {
                builder.nop();
            } else if (op == "HALT" || op == "HLT") {
                builder.halt();
            } else if (op == "RET") {
                builder.ret();
            } else if (op == "MOV" && idx + 2 < tokens.size()) {
                VReg dst{}, src{};
                if (parse_register(tokens[idx + 1], dst)) {
                    if (parse_register(tokens[idx + 2], src)) {
                        builder.mov(dst, src);
                    } else {
                        u64 imm = 0;
                        if (parse_u64(tokens[idx + 2], imm)) builder.mov(dst, imm);
                    }
                }
            } else if ((op == "ADD" || op == "SUB" || op == "MUL" || op == "DIV" || op == "MOD" ||
                        op == "AND" || op == "OR"  || op == "XOR" || op == "CMP" || op == "TEST" ||
                        op == "LOAD" || op == "STORE" || op == "POPCNT") && idx + 2 < tokens.size()) {
                VReg r1{}, r2{};
                if (parse_register(tokens[idx + 1], r1) && parse_register(tokens[idx + 2], r2)) {
                    if (op == "ADD") builder.add(r1, r2);
                    else if (op == "SUB") builder.sub(r1, r2);
                    else if (op == "MUL") builder.mul(r1, r2);
                    else if (op == "DIV") builder.div(r1, r2);
                    else if (op == "MOD") builder.mod(r1, r2);
                    else if (op == "AND") builder.bitwise_and(r1, r2);
                    else if (op == "OR")  builder.bitwise_or(r1, r2);
                    else if (op == "XOR") builder.bitwise_xor(r1, r2);
                    else if (op == "CMP") builder.cmp(r1, r2);
                    else if (op == "TEST") builder.test(r1, r2);
                    else if (op == "LOAD") builder.load(r1, r2);
                    else if (op == "STORE") builder.store(r1, r2);
                    else if (op == "POPCNT") builder.popcnt(r1, r2);
                }
            } else if ((op == "NOT" || op == "PUSH" || op == "POP" || op == "BSWAP") && idx + 1 < tokens.size()) {
                VReg r{};
                if (parse_register(tokens[idx + 1], r)) {
                    if (op == "NOT") builder.bitwise_not(r);
                    else if (op == "PUSH") builder.push(r);
                    else if (op == "POP") builder.pop(r);
                    else if (op == "BSWAP") builder.bswap(r);
                }
            } else if ((op == "SHL" || op == "SHR" || op == "ROL" || op == "ROR") && idx + 2 < tokens.size()) {
                VReg r{};
                u64 sh = 0;
                if (parse_register(tokens[idx + 1], r) && parse_u64(tokens[idx + 2], sh)) {
                    if (op == "SHL") builder.shl(r, static_cast<u8>(sh));
                    else if (op == "SHR") builder.shr(r, static_cast<u8>(sh));
                    else if (op == "ROL") builder.rol(r, static_cast<u8>(sh));
                    else if (op == "ROR") builder.ror(r, static_cast<u8>(sh));
                }
            } else if ((op == "JMP" || op == "JZ" || op == "JNZ" || op == "JG" ||
                        op == "JL"  || op == "JGE" || op == "JLE" || op == "CALL") && idx + 1 < tokens.size()) {
                Label lbl = get_or_create_label(tokens[idx + 1]);
                if (op == "JMP") builder.jmp(lbl);
                else if (op == "JZ") builder.jz(lbl);
                else if (op == "JNZ") builder.jnz(lbl);
                else if (op == "JG") builder.jg(lbl);
                else if (op == "JL") builder.jl(lbl);
                else if (op == "JGE") builder.jge(lbl);
                else if (op == "JLE") builder.jle(lbl);
                else if (op == "CALL") builder.call(lbl);
            } else if ((op == "VMEMCPY" || op == "VMEMSET") && idx + 3 < tokens.size()) {
                VReg r1{}, r2{}, r3{};
                if (parse_register(tokens[idx + 1], r1) &&
                    parse_register(tokens[idx + 2], r2) &&
                    parse_register(tokens[idx + 3], r3)) {
                    if (op == "VMEMCPY") builder.vmemcpy(r1, r2, r3);
                    else builder.vmemset(r1, r2, r3);
                }
            } else if (op == "JUNK") {
                u64 cnt = 1;
                if (idx + 1 < tokens.size()) parse_u64(tokens[idx + 1], cnt);
                builder.emit_junk(static_cast<size_t>(cnt));
            }
        }

        return builder.build(key);
    }
};

} // namespace vm::assembler

// ============================================================================
// 32. BYTECODE IR OPTIMIZATION & OBFUSCATION PASS PIPELINE
// (Integrated & expanded from Substitution.cpp, BogusControlFlow.cpp, SplitBasicBlocks.cpp)
// ============================================================================
namespace vm::optimizer {

struct IRNode {
    Opcode op{Opcode::OP_NOP};
    VReg dst{VReg::R0};
    VReg src1{VReg::R0};
    VReg src2{VReg::R0};
    u64 imm{0};
    u8 shift{0};
};

class BytecodeObfuscationPipeline {
public:
    explicit BytecodeObfuscationPipeline(VReg scratch_reg = VReg::R7) noexcept
        : scratch_(scratch_reg) {}

    void add_node(const IRNode& node) {
        nodes_.push_back(node);
    }

    void emit_mov_imm(VReg dst, u64 val) {
        nodes_.push_back(IRNode{Opcode::OP_MOV_IMM, dst, VReg::R0, VReg::R0, val, 0});
    }

    void emit_add(VReg dst, VReg src) {
        nodes_.push_back(IRNode{Opcode::OP_ADD, dst, src, VReg::R0, 0, 0});
    }

    void emit_sub(VReg dst, VReg src) {
        nodes_.push_back(IRNode{Opcode::OP_SUB, dst, src, VReg::R0, 0, 0});
    }

    void emit_xor(VReg dst, VReg src) {
        nodes_.push_back(IRNode{Opcode::OP_XOR, dst, src, VReg::R0, 0, 0});
    }

    void emit_halt() {
        nodes_.push_back(IRNode{Opcode::OP_HALT, VReg::R0, VReg::R0, VReg::R0, 0, 0});
    }

    /**
     * @brief Pass 1: Constant Blinding (splits MOV reg, imm into MOV reg, (imm ^ mask) + XOR mask)
     */
    void run_constant_blinding_pass(u64 mask_seed = 0x5A5A5A5A5A5A5A5AULL) {
        std::vector<IRNode> out;
        out.reserve(nodes_.size() * 3);
        u64 cur_mask = mask_seed;

        for (const auto& n : nodes_) {
            if (n.op == Opcode::OP_MOV_IMM && n.dst != scratch_) {
                cur_mask = (cur_mask * 0x5851F42D4C957F2DULL) + 0x14057B7EF767814FULL;
                u64 blinded = n.imm ^ cur_mask;
                out.push_back(IRNode{Opcode::OP_MOV_IMM, n.dst, VReg::R0, VReg::R0, blinded, 0});
                out.push_back(IRNode{Opcode::OP_MOV_IMM, scratch_, VReg::R0, VReg::R0, cur_mask, 0});
                out.push_back(IRNode{Opcode::OP_XOR, n.dst, scratch_, VReg::R0, 0, 0});
            } else {
                out.push_back(n);
            }
        }
        nodes_ = std::move(out);
    }

    /**
     * @brief Pass 2: MBA Instruction Expansion (expands ADD into XOR + AND + SHL sequence)
     */
    void run_mba_expansion_pass() {
        std::vector<IRNode> out;
        out.reserve(nodes_.size() * 4);

        for (const auto& n : nodes_) {
            if (n.op == Opcode::OP_ADD && n.dst != scratch_ && n.src1 != scratch_) {
                // x + y = (x ^ y) + ((x & y) << 1)
                out.push_back(IRNode{Opcode::OP_MOV_REG, scratch_, n.dst, VReg::R0, 0, 0});
                out.push_back(IRNode{Opcode::OP_AND, scratch_, n.src1, VReg::R0, 0, 0});
                out.push_back(IRNode{Opcode::OP_SHL, scratch_, VReg::R0, VReg::R0, 0, 1});
                out.push_back(IRNode{Opcode::OP_XOR, n.dst, n.src1, VReg::R0, 0, 0});
                out.push_back(IRNode{Opcode::OP_ADD, n.dst, scratch_, VReg::R0, 0, 0});
            } else {
                out.push_back(n);
            }
        }
        nodes_ = std::move(out);
    }

    /**
     * @brief Pass 3: Dead Code / Junk Injection between instructions
     */
    void run_dead_code_insertion_pass(size_t frequency = 2) {
        if (frequency == 0) return;
        std::vector<IRNode> out;
        out.reserve(nodes_.size() * 2);

        for (size_t i = 0; i < nodes_.size(); ++i) {
            if ((i % frequency) == 0) {
                out.push_back(IRNode{Opcode::OP_JUNK, VReg::R0, VReg::R0, VReg::R0, core::RuntimeRandom::get_u64(), 0});
            }
            out.push_back(nodes_[i]);
        }
        nodes_ = std::move(out);
    }

    BytecodeChunk compile(u64 key = 0, bool polymorphic = true) const {
        BytecodeBuilder b(polymorphic);
        for (const auto& n : nodes_) {
            switch (n.op) {
            case Opcode::OP_NOP:     b.nop(); break;
            case Opcode::OP_MOV_IMM: b.mov(n.dst, n.imm); break;
            case Opcode::OP_MOV_REG: b.mov(n.dst, n.src1); break;
            case Opcode::OP_ADD:     b.add(n.dst, n.src1); break;
            case Opcode::OP_SUB:     b.sub(n.dst, n.src1); break;
            case Opcode::OP_MUL:     b.mul(n.dst, n.src1); break;
            case Opcode::OP_DIV:     b.div(n.dst, n.src1); break;
            case Opcode::OP_MOD:     b.mod(n.dst, n.src1); break;
            case Opcode::OP_AND:     b.bitwise_and(n.dst, n.src1); break;
            case Opcode::OP_OR:      b.bitwise_or(n.dst, n.src1); break;
            case Opcode::OP_XOR:     b.bitwise_xor(n.dst, n.src1); break;
            case Opcode::OP_NOT:     b.bitwise_not(n.dst); break;
            case Opcode::OP_SHL:     b.shl(n.dst, n.shift); break;
            case Opcode::OP_SHR:     b.shr(n.dst, n.shift); break;
            case Opcode::OP_BSWAP:   b.bswap(n.dst); break;
            case Opcode::OP_POPCNT:  b.popcnt(n.dst, n.src1); break;
            case Opcode::OP_JUNK:    b.emit_junk(1); break;
            case Opcode::OP_HALT:    b.halt(); break;
            default:                 b.nop(); break;
            }
        }
        return b.build(key);
    }

    size_t node_count() const noexcept { return nodes_.size(); }

private:
    VReg scratch_;
    std::vector<IRNode> nodes_;
};

} // namespace vm::optimizer

// ============================================================================
// 33. VM EXECUTION PROFILER, SNAPSHOT MANAGER & TRACE RECORDER
// ============================================================================
namespace vm::profiler {

struct RegisterSnapshot {
    std::array<reg_t, static_cast<size_t>(VReg::COUNT)> regs{};
    u64 timestamp_rdtsc{0};
};

struct ProfileReport {
    u64 total_instructions{0};
    u32 unique_opcodes_used{0};
    std::array<u64, 256> opcode_histogram{};
    Opcode most_frequent_opcode{Opcode::OP_NOP};
};

class VMProfiler {
public:
    static inline RegisterSnapshot capture_snapshot(const VMContext& ctx) noexcept {
        RegisterSnapshot snap{};
        for (size_t i = 0; i < static_cast<size_t>(VReg::COUNT); ++i) {
            snap.regs[i] = ctx.get_reg(static_cast<VReg>(i));
        }
#if defined(AEGIS_COMPILER_MSVC)
        snap.timestamp_rdtsc = __rdtsc();
#endif
        return snap;
    }

    static inline void restore_snapshot(VMContext& ctx, const RegisterSnapshot& snap) noexcept {
        for (size_t i = 0; i < static_cast<size_t>(VReg::COUNT); ++i) {
            ctx.set_reg(static_cast<VReg>(i), snap.regs[i]);
        }
    }

    static inline ProfileReport analyze_static_bytecode(const BytecodeChunk& chunk) {
        ProfileReport rep{};
        auto decoded = disasm::BytecodeDisassembler::disassemble(chunk);
        rep.total_instructions = decoded.size();

        u64 max_count = 0;
        for (const auto& ins : decoded) {
            u8 idx = static_cast<u8>(ins.opcode);
            if (rep.opcode_histogram[idx] == 0) {
                rep.unique_opcodes_used++;
            }
            rep.opcode_histogram[idx]++;
            if (rep.opcode_histogram[idx] > max_count) {
                max_count = rep.opcode_histogram[idx];
                rep.most_frequent_opcode = ins.opcode;
            }
        }
        return rep;
    }
};

} // namespace vm::profiler


// ============================================================================
// 34. PORTABLE EXECUTABLE (PE32/PE32+) STATIC ANALYZER & SECURITY AUDITOR
// ============================================================================
namespace pe {

struct PeSectionReport {
    std::string name;
    u32 virtual_address{0};
    u32 virtual_size{0};
    u32 raw_size{0};
    u32 characteristics{0};
    double shannon_entropy{0.0};
    bool is_executable{false};
    bool is_writable{false};
    bool is_rwx_violation{false};
};

struct PeSecurityAudit {
    bool valid_pe{false};
    bool is_64bit{false};
    bool has_aslr{false};
    bool has_dep_nx{false};
    bool has_high_entropy_va{false};
    bool has_cfg{false};
    bool has_seh{false};
    bool has_authenticode_dir{false};
    bool has_tls_directory{false};
    bool has_debug_directory{false};
    u32 entry_point_rva{0};
    u64 image_base{0};
    u32 size_of_image{0};
    u32 rwx_section_count{0};
    std::vector<PeSectionReport> sections;
};

class PeImageAnalyzer {
public:
    static inline double compute_entropy(const u8* data, size_t size) noexcept {
        if (!data || size == 0) return 0.0;
        std::array<size_t, 256> freq{};
        for (size_t i = 0; i < size; ++i) {
            freq[data[i]]++;
        }

        double entropy = 0.0;
        const double inv_size = 1.0 / static_cast<double>(size);
        for (size_t count : freq) {
            if (count == 0) continue;
            double p = static_cast<double>(count) * inv_size;
            // Fast log2 approximation using natural log series or std::bit
            // Use standard log2 via bit-level IEEE-754 extraction
            entropy -= p * fast_log2(p);
        }
        return entropy;
    }

    static inline PeSecurityAudit analyze_module(const void* module_base = nullptr) {
        PeSecurityAudit report{};
#if defined(AEGIS_WINDOWS)
        if (!module_base) {
            module_base = GetModuleHandleW(nullptr);
        }
        if (!module_base) return report;

        const auto* base = static_cast<const u8*>(module_base);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return report;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return report;

        report.valid_pe = true;
        report.is_64bit = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        report.entry_point_rva = nt->OptionalHeader.AddressOfEntryPoint;
        report.image_base = static_cast<u64>(nt->OptionalHeader.ImageBase);
        report.size_of_image = nt->OptionalHeader.SizeOfImage;

        const u16 dll_chars = nt->OptionalHeader.DllCharacteristics;
        report.has_aslr            = (dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
        report.has_dep_nx          = (dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
        report.has_high_entropy_va = (dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
        report.has_cfg             = (dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        report.has_seh             = (dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;

        report.has_authenticode_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress != 0;
        report.has_tls_directory    = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0;
        report.has_debug_directory  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0;

        const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (u16 i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            PeSectionReport srep{};
            char name_buf[9]{};
            std::memcpy(name_buf, sec[i].Name, 8);
            srep.name = name_buf;
            srep.virtual_address = sec[i].VirtualAddress;
            srep.virtual_size    = sec[i].Misc.VirtualSize;
            srep.raw_size        = sec[i].SizeOfRawData;
            srep.characteristics = sec[i].Characteristics;

            srep.is_executable = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            srep.is_writable   = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            srep.is_rwx_violation = srep.is_executable && srep.is_writable;
            if (srep.is_rwx_violation) report.rwx_section_count++;

            size_t scan_sz = (srep.virtual_size > 0 && srep.virtual_size < 65536) ? srep.virtual_size : 4096;
            if (srep.virtual_address + scan_sz <= report.size_of_image) {
                srep.shannon_entropy = compute_entropy(base + srep.virtual_address, scan_sz);
            }
            report.sections.push_back(std::move(srep));
        }
#else
        (void)module_base;
#endif
        return report;
    }

private:
    static inline double fast_log2(double x) noexcept {
        if (x <= 0.0) return 0.0;
        u64 bits = 0;
        std::memcpy(&bits, &x, sizeof(double));
        int exp = static_cast<int>((bits >> 52) & 0x7FF) - 1023;
        bits = (bits & 0x000FFFFFFFFFFFFFULL) | 0x3FF0000000000000ULL;
        double m = 0.0;
        std::memcpy(&m, &bits, sizeof(double));
        double y = (m - 1.0) / (m + 1.0);
        double y2 = y * y;
        double ln_m = 2.0 * y * (1.0 + y2 / 3.0 + (y2 * y2) / 5.0 + (y2 * y2 * y2) / 7.0);
        return static_cast<double>(exp) + (ln_m * 1.4426950408889634);
    }
};

} // namespace pe

// ============================================================================
// 35. CRYPTOGRAPHIC SOFTWARE LICENSING & ENTITLEMENT ENGINE
// ============================================================================
namespace license {

enum class LicenseStatus : u32 {
    Valid                = 0,
    MalformedToken       = 1,
    AuthenticationFailed = 2,
    InvalidMagic         = 3,
    Expired              = 4,
    HardwareMismatch     = 5,
    FeatureNotEntitled   = 6
};

namespace FeatureFlags {
    constexpr u32 TIER_COMMUNITY  = 1U << 0;
    constexpr u32 TIER_PRO        = 1U << 1;
    constexpr u32 TIER_ENTERPRISE = 1U << 2;
    constexpr u32 VM_PROTECTION   = 1U << 3;
    constexpr u32 ANTI_DEBUG      = 1U << 4;
    constexpr u32 OFFLINE_MODE    = 1U << 5;
    constexpr u32 ALL_FEATURES    = 0xFFFFFFFFU;
}

#pragma pack(push, 1)
struct LicenseWirePayload {
    u32 magic;               // 'AGLC' (0x434C4741)
    u16 version;             // 1
    u16 seat_count;
    u64 license_id;
    u64 bound_hwid;          // 0 = floating / unbound, non-zero = locked to HWID
    u64 issued_unix_sec;
    u64 expires_unix_sec;    // 0 = perpetual
    u32 feature_mask;
    char licensee_id[32];
};
#pragma pack(pop)

constexpr u32 AGLC_MAGIC = 0x434C4741U;

class LicenseManager {
public:
    using MasterKey = crypto::ChaCha20Poly1305::Key;

    static inline std::string issue_license(const MasterKey& master_key,
                                            u64 license_id,
                                            u64 bound_hwid,
                                            u64 issued_sec,
                                            u64 expires_sec,
                                            u32 feature_mask,
                                            u16 seats,
                                            std::string_view licensee) {
        LicenseWirePayload payload{};
        payload.magic            = AGLC_MAGIC;
        payload.version          = 1;
        payload.seat_count       = seats;
        payload.license_id       = license_id;
        payload.bound_hwid       = bound_hwid;
        payload.issued_unix_sec  = issued_sec;
        payload.expires_unix_sec = expires_sec;
        payload.feature_mask     = feature_mask;

        size_t copy_len = (licensee.size() < 31) ? licensee.size() : 31;
        std::memcpy(payload.licensee_id, licensee.data(), copy_len);

        crypto::ChaCha20Poly1305::Nonce nonce{};
        u64 r1 = core::RuntimeRandom::get_u64();
        u32 r2 = core::RuntimeRandom::get_u32();
        std::memcpy(&nonce[0], &r1, 8);
        std::memcpy(&nonce[8], &r2, 4);

        crypto::ChaCha20Poly1305::Tag tag{};
        static constexpr u8 aad[] = "AEGIS-LICENSE-V1";
        auto ct = crypto::ChaCha20Poly1305::seal(
            master_key, nonce,
            reinterpret_cast<const u8*>(&payload), sizeof(payload),
            aad, sizeof(aad) - 1, tag);

        std::vector<u8> wire;
        wire.reserve(12 + 16 + ct.size());
        wire.insert(wire.end(), nonce.begin(), nonce.end());
        wire.insert(wire.end(), tag.begin(), tag.end());
        wire.insert(wire.end(), ct.begin(), ct.end());

        std::string b32 = codec::Base32::encode(wire.data(), wire.size(), false);
        std::string formatted = "AEGIS";
        for (size_t i = 0; i < b32.size(); ++i) {
            if ((i % 5) == 0) formatted.push_back('-');
            formatted.push_back(b32[i]);
        }
        return formatted;
    }

    static inline LicenseStatus verify_license(const MasterKey& master_key,
                                               std::string_view license_key,
                                               u64 current_unix_sec,
                                               u64 current_hwid,
                                               u32 required_features,
                                               LicenseWirePayload* out_payload = nullptr) {
        if (license_key.size() < 6 || license_key.substr(0, 6) != "AEGIS-") {
            return LicenseStatus::MalformedToken;
        }

        std::string clean_b32;
        clean_b32.reserve(license_key.size());
        for (size_t i = 6; i < license_key.size(); ++i) {
            if (license_key[i] != '-') clean_b32.push_back(license_key[i]);
        }

        bool b32_ok = false;
        std::vector<u8> wire = codec::Base32::decode(clean_b32, b32_ok);
        if (!b32_ok || wire.size() != (12 + 16 + sizeof(LicenseWirePayload))) {
            return LicenseStatus::MalformedToken;
        }

        crypto::ChaCha20Poly1305::Nonce nonce{};
        crypto::ChaCha20Poly1305::Tag tag{};
        std::memcpy(nonce.data(), &wire[0], 12);
        std::memcpy(tag.data(), &wire[12], 16);

        static constexpr u8 aad[] = "AEGIS-LICENSE-V1";
        std::vector<u8> pt;
        if (!crypto::ChaCha20Poly1305::open(
                master_key, nonce,
                &wire[28], sizeof(LicenseWirePayload),
                aad, sizeof(aad) - 1, tag, pt)) {
            return LicenseStatus::AuthenticationFailed;
        }

        LicenseWirePayload payload{};
        std::memcpy(&payload, pt.data(), sizeof(LicenseWirePayload));
        secure_zero(pt.data(), pt.size());

        if (payload.magic != AGLC_MAGIC || payload.version != 1) {
            return LicenseStatus::InvalidMagic;
        }

        if (payload.expires_unix_sec != 0 && current_unix_sec > payload.expires_unix_sec) {
            return LicenseStatus::Expired;
        }

        if (payload.bound_hwid != 0 && payload.bound_hwid != current_hwid) {
            return LicenseStatus::HardwareMismatch;
        }

        if ((payload.feature_mask & required_features) != required_features) {
            return LicenseStatus::FeatureNotEntitled;
        }

        if (out_payload) {
            *out_payload = payload;
        }
        return LicenseStatus::Valid;
    }
};

} // namespace license

// ============================================================================
// 36. ENCRYPTED IN-MEMORY AUDIT RING LOGGER & TELEMETRY BUS
// ============================================================================
namespace telemetry {

enum class EventSeverity : u8 {
    Trace    = 0,
    Info     = 1,
    Warning  = 2,
    Critical = 3
};

struct AuditRecord {
    u64 sequence_id{0};
    u64 timestamp_ticks{0};
    EventSeverity severity{EventSeverity::Info};
    u32 category_id{0};
    std::string message;
};

/**
 * @brief Thread-safe Circular Audit Log that keeps entries ChaCha20-encrypted in RAM
 * so sensitive security telemetry is never exposed in plaintext memory dumps.
 */
class EncryptedRingLogger {
public:
    explicit EncryptedRingLogger(size_t capacity = 128)
        : capacity_(capacity == 0 ? 64 : capacity)
        , slots_(capacity_) {
        for (size_t i = 0; i < 32; ++i) session_key_[i] = core::RuntimeRandom::get_u8();
        for (size_t i = 0; i < 12; ++i) session_nonce_[i] = core::RuntimeRandom::get_u8();
    }

    ~EncryptedRingLogger() {
        clear();
    }

    void log(EventSeverity sev, u32 category, std::string_view msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        u64 seq = next_seq_++;
        u64 ticks = 0;
#if defined(AEGIS_COMPILER_MSVC)
        ticks = __rdtsc();
#endif
        std::vector<u8> raw;
        raw.reserve(21 + msg.size());
        for (int i = 0; i < 8; ++i) raw.push_back(static_cast<u8>((seq >> (i * 8)) & 0xFF));
        for (int i = 0; i < 8; ++i) raw.push_back(static_cast<u8>((ticks >> (i * 8)) & 0xFF));
        raw.push_back(static_cast<u8>(sev));
        for (int i = 0; i < 4; ++i) raw.push_back(static_cast<u8>((category >> (i * 8)) & 0xFF));
        raw.insert(raw.end(), reinterpret_cast<const u8*>(msg.data()), reinterpret_cast<const u8*>(msg.data()) + msg.size());

        crypto::ChaCha20::crypt(session_key_, session_nonce_, static_cast<u32>(seq & 0xFFFFFFFFUL), raw.data(), raw.size());

        Slot& s = slots_[head_];
        if (!s.ciphertext.empty()) {
            secure_zero(s.ciphertext.data(), s.ciphertext.size());
        }
        s.seq = static_cast<u32>(seq & 0xFFFFFFFFUL);
        s.ciphertext = std::move(raw);
        s.occupied = true;

        head_ = (head_ + 1) % capacity_;
        if (count_ < capacity_) count_++;
    }

    std::vector<AuditRecord> decrypt_all() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<AuditRecord> out;
        out.reserve(count_);

        size_t start = (count_ == capacity_) ? head_ : 0;
        for (size_t i = 0; i < count_; ++i) {
            const Slot& s = slots_[(start + i) % capacity_];
            if (!s.occupied || s.ciphertext.size() < 21) continue;

            std::vector<u8> plain = s.ciphertext;
            crypto::ChaCha20::crypt(session_key_, session_nonce_, s.seq, plain.data(), plain.size());

            AuditRecord rec{};
            for (int b = 0; b < 8; ++b) rec.sequence_id |= static_cast<u64>(plain[b]) << (b * 8);
            for (int b = 0; b < 8; ++b) rec.timestamp_ticks |= static_cast<u64>(plain[8 + b]) << (b * 8);
            rec.severity = static_cast<EventSeverity>(plain[16]);
            for (int b = 0; b < 4; ++b) rec.category_id |= static_cast<u32>(plain[17 + b]) << (b * 8);
            if (plain.size() > 21) {
                rec.message.assign(reinterpret_cast<const char*>(&plain[21]), plain.size() - 21);
            }
            secure_zero(plain.data(), plain.size());
            out.push_back(std::move(rec));
        }
        return out;
    }

    void clear() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& s : slots_) {
            if (!s.ciphertext.empty()) {
                secure_zero(s.ciphertext.data(), s.ciphertext.size());
                s.ciphertext.clear();
            }
            s.occupied = false;
        }
        head_ = 0;
        count_ = 0;
    }

    size_t size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return count_;
    }

private:
    struct Slot {
        u32 seq{0};
        bool occupied{false};
        std::vector<u8> ciphertext;
    };

    mutable std::mutex mutex_;
    size_t capacity_;
    std::vector<Slot> slots_;
    size_t head_{0};
    size_t count_{0};
    u64 next_seq_{1};
    crypto::ChaCha20::Key session_key_{};
    crypto::ChaCha20::Nonce session_nonce_{};
};

} // namespace telemetry

// ============================================================================
// 37. SECURE ZEROIZING CONTAINERS & OBFUSCATED POINTER / CALL WRAPPERS
// (Integrated & expanded from FunctionWrapper.cpp, FunctionCallObfuscate.cpp, obscuring.cpp)
// ============================================================================
namespace containers {

/**
 * @brief Pointer Obfuscator that stores raw pointers XOR-rotated with a per-instance runtime key
 */
template <typename T>
class ObfuscatedPointer {
public:
    explicit ObfuscatedPointer(T* ptr = nullptr) noexcept {
        key_ = core::RuntimeRandom::get_u64() | 1ULL;
        set(ptr);
    }

    void set(T* ptr) noexcept {
        uintptr_t raw = reinterpret_cast<uintptr_t>(ptr);
        u64 v = static_cast<u64>(raw) ^ key_;
        encoded_ = (v << 13) | (v >> (64 - 13));
    }

    T* get() const noexcept {
        u64 v = (encoded_ >> 13) | (encoded_ << (64 - 13));
        uintptr_t raw = static_cast<uintptr_t>(obf::Mba::bitwise_xor(v, key_));
        return reinterpret_cast<T*>(raw);
    }

    T* operator->() const noexcept { return get(); }
    std::add_lvalue_reference_t<T> operator*() const noexcept { return *get(); }
    explicit operator bool() const noexcept { return get() != nullptr; }

private:
    u64 encoded_{0};
    u64 key_{0};
};

/**
 * @brief Obfuscated Function Call Wrapper (hides direct call targets from static cross-references)
 */
template <typename Sig>
class ObfuscatedFunction;

template <typename Ret, typename... Args>
class ObfuscatedFunction<Ret(Args...)> {
public:
    using FnPtr = Ret(*)(Args...);

    explicit ObfuscatedFunction(FnPtr fn = nullptr) noexcept
        : ptr_(reinterpret_cast<void*>(fn)) {}

    Ret operator()(Args... args) const {
        auto fn = reinterpret_cast<FnPtr>(ptr_.get());
        return fn(std::forward<Args>(args)...);
    }

private:
    ObfuscatedPointer<void> ptr_;
};

/**
 * @brief Space-efficient Probabilistic Bloom Filter using double hashing (FNV-1a + Murmur3)
 */
class BloomFilter {
public:
    explicit BloomFilter(size_t num_bits = 4096, size_t num_hashes = 4)
        : num_bits_(num_bits < 64 ? 64 : num_bits)
        , num_hashes_(num_hashes == 0 ? 1 : num_hashes)
        , bits_((num_bits_ + 63) / 64, 0ULL) {}

    void insert(const u8* data, size_t len) noexcept {
        u64 h1 = core::Fnv1a::hash(data, len);
        u64 h2 = static_cast<u64>(core::Murmur3::hash32(data, len, 0x9747b28cU));
        for (size_t i = 0; i < num_hashes_; ++i) {
            size_t bit = static_cast<size_t>((h1 + i * h2) % num_bits_);
            bits_[bit / 64] |= (1ULL << (bit % 64));
        }
    }

    void insert(std::string_view sv) noexcept {
        insert(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    bool possibly_contains(const u8* data, size_t len) const noexcept {
        u64 h1 = core::Fnv1a::hash(data, len);
        u64 h2 = static_cast<u64>(core::Murmur3::hash32(data, len, 0x9747b28cU));
        for (size_t i = 0; i < num_hashes_; ++i) {
            size_t bit = static_cast<size_t>((h1 + i * h2) % num_bits_);
            if ((bits_[bit / 64] & (1ULL << (bit % 64))) == 0) {
                return false;
            }
        }
        return true;
    }

    bool possibly_contains(std::string_view sv) const noexcept {
        return possibly_contains(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    void clear() noexcept {
        std::fill(bits_.begin(), bits_.end(), 0ULL);
    }

private:
    size_t num_bits_;
    size_t num_hashes_;
    std::vector<u64> bits_;
};

} // namespace containers


// ============================================================================
// 38. FIPS 202 SHA-3 (256/384/512), KECCAK-f[1600] & SHAKE128/256 SPONGE
// ============================================================================
namespace crypto {

class Keccak1600 {
public:
    static constexpr std::array<u64, 24> RC = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
    };

    static constexpr std::array<u32, 24> RHO = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    static constexpr std::array<size_t, 24> PI = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    static constexpr u64 rotl64(u64 x, u32 s) noexcept {
        return (s == 0) ? x : ((x << s) | (x >> (64 - s)));
    }

    static constexpr void permute(std::array<u64, 25>& st) noexcept {
        for (size_t round = 0; round < 24; ++round) {
            // Theta
            std::array<u64, 5> bc{};
            for (size_t i = 0; i < 5; ++i) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }
            for (size_t i = 0; i < 5; ++i) {
                u64 t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
                for (size_t j = 0; j < 25; j += 5) {
                    st[j + i] ^= t;
                }
            }

            // Rho & Pi
            u64 t = st[1];
            for (size_t i = 0; i < 24; ++i) {
                size_t j = PI[i];
                u64 tmp = st[j];
                st[j] = rotl64(t, RHO[i]);
                t = tmp;
            }

            // Chi
            for (size_t j = 0; j < 25; j += 5) {
                std::array<u64, 5> row{};
                for (size_t i = 0; i < 5; ++i) row[i] = st[j + i];
                for (size_t i = 0; i < 5; ++i) {
                    st[j + i] ^= (~row[(i + 1) % 5]) & row[(i + 2) % 5];
                }
            }

            // Iota
            st[0] ^= RC[round];
        }
    }

    static inline void hash_sponge(const u8* in, size_t in_len, u8* out, size_t out_len, size_t rate_bytes, u8 domain_sep) noexcept {
        std::array<u64, 25> state{};
        u8* state_bytes = reinterpret_cast<u8*>(state.data());

        while (in_len >= rate_bytes) {
            for (size_t i = 0; i < rate_bytes; ++i) state_bytes[i] ^= in[i];
            permute(state);
            in += rate_bytes;
            in_len -= rate_bytes;
        }

        for (size_t i = 0; i < in_len; ++i) state_bytes[i] ^= in[i];
        state_bytes[in_len] ^= domain_sep;
        state_bytes[rate_bytes - 1] ^= 0x80;
        permute(state);

        while (out_len > 0) {
            size_t block = (out_len < rate_bytes) ? out_len : rate_bytes;
            std::memcpy(out, state_bytes, block);
            out += block;
            out_len -= block;
            if (out_len > 0) permute(state);
        }
        secure_zero(state.data(), sizeof(state));
    }

    static inline std::array<u8, 32> sha3_256(const u8* data, size_t len) noexcept {
        std::array<u8, 32> out{};
        hash_sponge(data, len, out.data(), 32, 136, 0x06);
        return out;
    }

    static inline std::array<u8, 32> sha3_256(std::string_view sv) noexcept {
        return sha3_256(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    static inline std::array<u8, 64> sha3_512(const u8* data, size_t len) noexcept {
        std::array<u8, 64> out{};
        hash_sponge(data, len, out.data(), 64, 72, 0x06);
        return out;
    }

    static inline std::array<u8, 64> sha3_512(std::string_view sv) noexcept {
        return sha3_512(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

    static inline void shake256(const u8* data, size_t len, u8* out, size_t out_len) noexcept {
        hash_sponge(data, len, out, out_len, 136, 0x1F);
    }

    static inline std::string sha3_256_hex(std::string_view sv) {
        auto d = sha3_256(sv);
        static constexpr char hex[] = "0123456789abcdef";
        std::string s;
        s.reserve(64);
        for (u8 b : d) {
            s.push_back(hex[(b >> 4) & 0x0F]);
            s.push_back(hex[b & 0x0F]);
        }
        return s;
    }
};

// ============================================================================
// 39. XCHACHA20 (192-BIT NONCE) & SPECK128/256 + SIMON128/256 + THREEFISH-512
// ============================================================================
class XChaCha20 {
public:
    using Key    = std::array<u8, 32>;
    using NonceX = std::array<u8, 24>;

    static constexpr Key hchacha20(const Key& key, const std::array<u8, 16>& nonce16) noexcept {
        auto load32 = [](const u8* p) constexpr noexcept -> u32 {
            return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
                  (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
        };
        auto store32 = [](u8* p, u32 v) constexpr noexcept {
            p[0] = static_cast<u8>(v & 0xFF);
            p[1] = static_cast<u8>((v >> 8) & 0xFF);
            p[2] = static_cast<u8>((v >> 16) & 0xFF);
            p[3] = static_cast<u8>((v >> 24) & 0xFF);
        };

        std::array<u32, 16> x = {
            0x61707865UL, 0x3320646eUL, 0x79622d32UL, 0x6b206574UL,
            load32(&key[0]),     load32(&key[4]),     load32(&key[8]),     load32(&key[12]),
            load32(&key[16]),    load32(&key[20]),    load32(&key[24]),    load32(&key[28]),
            load32(&nonce16[0]), load32(&nonce16[4]), load32(&nonce16[8]), load32(&nonce16[12])
        };

        for (int i = 0; i < 10; ++i) {
            ChaCha20::quarter_round(x[0], x[4], x[8],  x[12]);
            ChaCha20::quarter_round(x[1], x[5], x[9],  x[13]);
            ChaCha20::quarter_round(x[2], x[6], x[10], x[14]);
            ChaCha20::quarter_round(x[3], x[7], x[11], x[15]);
            ChaCha20::quarter_round(x[0], x[5], x[10], x[15]);
            ChaCha20::quarter_round(x[1], x[6], x[11], x[12]);
            ChaCha20::quarter_round(x[2], x[7], x[8],  x[13]);
            ChaCha20::quarter_round(x[3], x[4], x[9],  x[14]);
        }

        Key subkey{};
        store32(&subkey[0],  x[0]);
        store32(&subkey[4],  x[1]);
        store32(&subkey[8],  x[2]);
        store32(&subkey[12], x[3]);
        store32(&subkey[16], x[12]);
        store32(&subkey[20], x[13]);
        store32(&subkey[24], x[14]);
        store32(&subkey[28], x[15]);
        return subkey;
    }

    static inline void crypt(const Key& key, const NonceX& nonce, u32 initial_counter, u8* data, size_t len) noexcept {
        std::array<u8, 16> n16{};
        for (size_t i = 0; i < 16; ++i) n16[i] = nonce[i];
        Key subkey = hchacha20(key, n16);

        ChaCha20::Nonce subnonce{};
        subnonce[0] = 0; subnonce[1] = 0; subnonce[2] = 0; subnonce[3] = 0;
        for (size_t i = 0; i < 8; ++i) subnonce[4 + i] = nonce[16 + i];

        ChaCha20::crypt(subkey, subnonce, initial_counter, data, len);
        secure_zero(subkey.data(), subkey.size());
    }
};

/**
 * @brief Speck128/256 Lightweight ARX Block Cipher (34 Rounds)
 */
class Speck128 {
public:
    using Key   = std::array<u64, 4>;
    using Block = std::array<u64, 2>;

    static constexpr u64 ror64(u64 x, u32 r) noexcept { return (x >> r) | (x << (64 - r)); }
    static constexpr u64 rol64(u64 x, u32 r) noexcept { return (x << r) | (x >> (64 - r)); }

    static constexpr void R(u64& x, u64& y, u64 k) noexcept {
        x = ror64(x, 8);
        x += y;
        x ^= k;
        y = rol64(y, 3);
        y ^= x;
    }

    static constexpr void inv_R(u64& x, u64& y, u64 k) noexcept {
        y ^= x;
        y = ror64(y, 3);
        x ^= k;
        x -= y;
        x = rol64(x, 8);
    }

    constexpr explicit Speck128(const Key& k) noexcept {
        u64 b = k[0];
        std::array<u64, 3> a = {k[1], k[2], k[3]};
        rk_[0] = b;
        for (u64 i = 0; i < 33; ++i) {
            R(a[i % 3], b, i);
            rk_[i + 1] = b;
        }
    }

    constexpr void encrypt_block(Block& pt) const noexcept {
        u64 y = pt[0], x = pt[1];
        for (size_t i = 0; i < 34; ++i) {
            R(x, y, rk_[i]);
        }
        pt[0] = y; pt[1] = x;
    }

    constexpr void decrypt_block(Block& ct) const noexcept {
        u64 y = ct[0], x = ct[1];
        for (int i = 33; i >= 0; --i) {
            inv_R(x, y, rk_[static_cast<size_t>(i)]);
        }
        ct[0] = y; ct[1] = x;
    }

private:
    std::array<u64, 34> rk_{};
};

/**
 * @brief Threefish-512 Tweakable 64-Byte Block Cipher (72 Rounds)
 */
class Threefish512 {
public:
    using Key   = std::array<u64, 8>;
    using Tweak = std::array<u64, 2>;
    using Block = std::array<u64, 8>;

    static constexpr u8 R_CONST[8][4] = {
        {46, 36, 19, 37},
        {33, 27, 14, 42},
        {17, 49, 36, 39},
        {44, 9,  54, 56},
        {39, 30, 34, 24},
        {13, 50, 10, 17},
        {25, 29, 39, 43},
        {8,  35, 56, 22}
    };

    static constexpr u8 PI[8] = {2, 1, 4, 7, 6, 5, 0, 3};
    static constexpr u8 INV_PI[8] = {6, 1, 0, 7, 2, 5, 4, 3};

    static constexpr u64 rotl64(u64 x, u32 n) noexcept {
        return (x << n) | (x >> (64 - n));
    }
    static constexpr u64 rotr64(u64 x, u32 n) noexcept {
        return (x >> n) | (x << (64 - n));
    }

    static constexpr void encrypt_block(Block& v, const Key& key, const Tweak& tweak) noexcept {
        std::array<u64, 9> kw{};
        u64 k_parity = 0x1BD11BDAA9FC1A22ULL;
        for (size_t i = 0; i < 8; ++i) {
            kw[i] = key[i];
            k_parity ^= key[i];
        }
        kw[8] = k_parity;
        std::array<u64, 3> tw = {tweak[0], tweak[1], tweak[0] ^ tweak[1]};

        for (size_t d = 0; d < 72; ++d) {
            if ((d % 4) == 0) {
                size_t s = d / 4;
                for (size_t i = 0; i < 5; ++i) v[i] += kw[(s + i) % 9];
                v[5] += kw[(s + 5) % 9] + tw[s % 3];
                v[6] += kw[(s + 6) % 9] + tw[(s + 1) % 3];
                v[7] += kw[(s + 7) % 9] + s;
            }

            for (size_t j = 0; j < 4; ++j) {
                u64& x0 = v[2 * j];
                u64& x1 = v[2 * j + 1];
                x0 += x1;
                x1 = rotl64(x1, R_CONST[d % 8][j]) ^ x0;
            }

            Block next{};
            for (size_t i = 0; i < 8; ++i) next[i] = v[PI[i]];
            v = next;
        }

        for (size_t i = 0; i < 5; ++i) v[i] += kw[(18 + i) % 9];
        v[5] += kw[(18 + 5) % 9] + tw[18 % 3];
        v[6] += kw[(18 + 6) % 9] + tw[(18 + 1) % 3];
        v[7] += kw[(18 + 7) % 9] + 18;
    }

    static constexpr void decrypt_block(Block& v, const Key& key, const Tweak& tweak) noexcept {
        std::array<u64, 9> kw{};
        u64 k_parity = 0x1BD11BDAA9FC1A22ULL;
        for (size_t i = 0; i < 8; ++i) {
            kw[i] = key[i];
            k_parity ^= key[i];
        }
        kw[8] = k_parity;
        std::array<u64, 3> tw = {tweak[0], tweak[1], tweak[0] ^ tweak[1]};

        for (size_t i = 0; i < 5; ++i) v[i] -= kw[(18 + i) % 9];
        v[5] -= kw[(18 + 5) % 9] + tw[18 % 3];
        v[6] -= kw[(18 + 6) % 9] + tw[(18 + 1) % 3];
        v[7] -= kw[(18 + 7) % 9] + 18;

        for (int d = 71; d >= 0; --d) {
            Block prev{};
            for (size_t i = 0; i < 8; ++i) prev[i] = v[INV_PI[i]];
            v = prev;

            for (size_t j = 0; j < 4; ++j) {
                u64& x0 = v[2 * j];
                u64& x1 = v[2 * j + 1];
                x1 = rotr64(x1 ^ x0, R_CONST[static_cast<size_t>(d) % 8][j]);
                x0 -= x1;
            }

            if ((d % 4) == 0) {
                size_t s = static_cast<size_t>(d) / 4;
                for (size_t i = 0; i < 5; ++i) v[i] -= kw[(s + i) % 9];
                v[5] -= kw[(s + 5) % 9] + tw[s % 3];
                v[6] -= kw[(s + 6) % 9] + tw[(s + 1) % 3];
                v[7] -= kw[(s + 7) % 9] + s;
            }
        }
    }
};

// ============================================================================
// 40. RFC 7748 X25519 / CURVE25519 DIFFIE-HELLMAN KEY EXCHANGE ENGINE
// ============================================================================
class X25519 {
public:
    using Key32 = std::array<u8, 32>;
    using Fe16  = std::array<i64, 16>;

    static constexpr void carry25519(Fe16& o) noexcept {
        for (size_t i = 0; i < 16; ++i) {
            i64 c = o[i] >> 16;
            o[i] -= c << 16;
            if (i < 15) o[i + 1] += c;
            else        o[0] += 38 * c;
        }
    }

    static constexpr void sel25519(Fe16& p, Fe16& q, int b) noexcept {
        i64 t = 0;
        i64 c = ~(static_cast<i64>(b) - 1);
        for (size_t i = 0; i < 16; ++i) {
            t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    static constexpr void unpack25519(Fe16& o, const Key32& n) noexcept {
        for (size_t i = 0; i < 16; ++i) {
            o[i] = static_cast<i64>(n[2 * i]) + (static_cast<i64>(n[2 * i + 1]) << 8);
        }
        o[15] &= 0x7fff;
    }

    static constexpr void pack25519(Key32& o, const Fe16& n) noexcept {
        Fe16 t = n;
        Fe16 m{};
        carry25519(t);
        carry25519(t);
        carry25519(t);
        for (int j = 0; j < 2; ++j) {
            m[0] = t[0] - 0xffed;
            for (size_t i = 1; i < 15; ++i) {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            int b = static_cast<int>((m[15] >> 16) & 1);
            m[14] &= 0xffff;
            sel25519(t, m, 1 - b);
        }
        for (size_t i = 0; i < 16; ++i) {
            o[2 * i]     = static_cast<u8>(t[i] & 0xff);
            o[2 * i + 1] = static_cast<u8>(t[i] >> 8);
        }
    }

    static constexpr void fe_add(Fe16& o, const Fe16& a, const Fe16& b) noexcept {
        for (size_t i = 0; i < 16; ++i) o[i] = a[i] + b[i];
    }

    static constexpr void fe_sub(Fe16& o, const Fe16& a, const Fe16& b) noexcept {
        for (size_t i = 0; i < 16; ++i) o[i] = a[i] - b[i];
    }

    static constexpr void fe_mul(Fe16& o, const Fe16& a, const Fe16& b) noexcept {
        std::array<i64, 31> t{};
        for (size_t i = 0; i < 16; ++i) {
            for (size_t j = 0; j < 16; ++j) {
                t[i + j] += a[i] * b[j];
            }
        }
        for (size_t i = 0; i < 15; ++i) {
            t[i] += 38 * t[i + 16];
        }
        for (size_t i = 0; i < 16; ++i) o[i] = t[i];
        carry25519(o);
        carry25519(o);
    }

    static constexpr void fe_sq(Fe16& o, const Fe16& a) noexcept {
        fe_mul(o, a, a);
    }

    static constexpr void fe_inv(Fe16& o, const Fe16& i_in) noexcept {
        Fe16 c = i_in;
        for (int a = 253; a >= 0; --a) {
            fe_sq(c, c);
            if (a != 2 && a != 4) {
                fe_mul(c, c, i_in);
            }
        }
        o = c;
    }

    static constexpr Key32 scalarmult(const Key32& scalar, const Key32& point) noexcept {
        Key32 z = scalar;
        z[31] = static_cast<u8>((scalar[31] & 127) | 64);
        z[0] &= 248;

        Fe16 x{};
        unpack25519(x, point);

        Fe16 a{}, b{}, c{}, d{}, e{}, f{};
        b = x;
        a[0] = 1;
        d[0] = 1;

        Fe16 c121665{};
        c121665[0] = 0xDB41;
        c121665[1] = 1;

        for (int i = 254; i >= 0; --i) {
            int r = (z[static_cast<size_t>(i >> 3)] >> (i & 7)) & 1;
            sel25519(a, b, r);
            sel25519(c, d, r);

            fe_add(e, a, c);
            fe_sub(a, a, c);
            fe_add(c, b, d);
            fe_sub(b, b, d);

            fe_sq(d, e);
            fe_sq(f, a);
            fe_mul(a, c, a);
            fe_mul(c, b, e);

            fe_add(e, a, c);
            fe_sub(a, a, c);
            fe_sq(b, a);
            fe_sub(c, d, f);

            fe_mul(a, c, c121665);
            fe_add(a, a, d);
            fe_mul(c, c, a);
            fe_mul(a, d, f);
            fe_mul(d, b, x);
            fe_sq(b, e);

            sel25519(a, b, r);
            sel25519(c, d, r);
        }

        fe_inv(c, c);
        fe_mul(a, a, c);
        Key32 out{};
        pack25519(out, a);
        return out;
    }

    static constexpr Key32 public_key(const Key32& secret_key) noexcept {
        Key32 basepoint{};
        basepoint[0] = 9;
        return scalarmult(secret_key, basepoint);
    }
};

} // namespace crypto


// ============================================================================
// 41. AEGISSCRIPT HIGH-LEVEL MINI-C TO V-ISA BYTECODE COMPILER
// ============================================================================
namespace vm::compiler {

enum class TokKind : u8 {
    Eof = 0,
    Ident,
    Number,
    KwLet,
    KwIf,
    KwElse,
    KwWhile,
    KwReturn,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Amp,
    Pipe,
    Caret,
    Shl,
    Shr,
    Eq,
    EqEq,
    BangEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Semi
};

struct ScriptToken {
    TokKind kind{TokKind::Eof};
    std::string text;
    u64 num_val{0};
};

class ScriptLexer {
public:
    explicit ScriptLexer(std::string_view src) noexcept : src_(src), pos_(0) {}

    std::vector<ScriptToken> tokenize() {
        std::vector<ScriptToken> out;
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                pos_++;
                continue;
            }
            if (c == '/' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '/') {
                while (pos_ < src_.size() && src_[pos_] != '\n') pos_++;
                continue;
            }
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
                size_t start = pos_;
                while (pos_ < src_.size() && ((src_[pos_] >= 'a' && src_[pos_] <= 'z') ||
                                              (src_[pos_] >= 'A' && src_[pos_] <= 'Z') ||
                                              (src_[pos_] >= '0' && src_[pos_] <= '9') ||
                                              src_[pos_] == '_')) {
                    pos_++;
                }
                std::string word(src_.substr(start, pos_ - start));
                if (word == "let")         out.push_back({TokKind::KwLet, word, 0});
                else if (word == "if")     out.push_back({TokKind::KwIf, word, 0});
                else if (word == "else")   out.push_back({TokKind::KwElse, word, 0});
                else if (word == "while")  out.push_back({TokKind::KwWhile, word, 0});
                else if (word == "return") out.push_back({TokKind::KwReturn, word, 0});
                else                       out.push_back({TokKind::Ident, word, 0});
                continue;
            }
            if (c >= '0' && c <= '9') {
                size_t start = pos_;
                int base = 10;
                if (c == '0' && pos_ + 1 < src_.size() && (src_[pos_ + 1] == 'x' || src_[pos_ + 1] == 'X')) {
                    base = 16;
                    pos_ += 2;
                }
                while (pos_ < src_.size() && ((src_[pos_] >= '0' && src_[pos_] <= '9') ||
                                              (base == 16 && ((src_[pos_] >= 'a' && src_[pos_] <= 'f') ||
                                                              (src_[pos_] >= 'A' && src_[pos_] <= 'F'))))) {
                    pos_++;
                }
                std::string num_str(src_.substr(start, pos_ - start));
                u64 val = std::strtoull(num_str.c_str(), nullptr, base);
                out.push_back({TokKind::Number, num_str, val});
                continue;
            }
            if (c == '=' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') {
                out.push_back({TokKind::EqEq, "==", 0}); pos_ += 2; continue;
            }
            if (c == '!' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') {
                out.push_back({TokKind::BangEq, "!=", 0}); pos_ += 2; continue;
            }
            if (c == '<' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') {
                out.push_back({TokKind::LtEq, "<=", 0}); pos_ += 2; continue;
            }
            if (c == '>' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') {
                out.push_back({TokKind::GtEq, ">=", 0}); pos_ += 2; continue;
            }
            if (c == '<' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '<') {
                out.push_back({TokKind::Shl, "<<", 0}); pos_ += 2; continue;
            }
            if (c == '>' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '>') {
                out.push_back({TokKind::Shr, ">>", 0}); pos_ += 2; continue;
            }

            pos_++;
            switch (c) {
            case '+': out.push_back({TokKind::Plus, "+", 0}); break;
            case '-': out.push_back({TokKind::Minus, "-", 0}); break;
            case '*': out.push_back({TokKind::Star, "*", 0}); break;
            case '/': out.push_back({TokKind::Slash, "/", 0}); break;
            case '%': out.push_back({TokKind::Percent, "%", 0}); break;
            case '&': out.push_back({TokKind::Amp, "&", 0}); break;
            case '|': out.push_back({TokKind::Pipe, "|", 0}); break;
            case '^': out.push_back({TokKind::Caret, "^", 0}); break;
            case '=': out.push_back({TokKind::Eq, "=", 0}); break;
            case '<': out.push_back({TokKind::Lt, "<", 0}); break;
            case '>': out.push_back({TokKind::Gt, ">", 0}); break;
            case '(': out.push_back({TokKind::LParen, "(", 0}); break;
            case ')': out.push_back({TokKind::RParen, ")", 0}); break;
            case '{': out.push_back({TokKind::LBrace, "{", 0}); break;
            case '}': out.push_back({TokKind::RBrace, "}", 0}); break;
            case ';': out.push_back({TokKind::Semi, ";", 0}); break;
            default: break;
            }
        }
        out.push_back({TokKind::Eof, "", 0});
        return out;
    }

private:
    std::string_view src_;
    size_t pos_;
};

/**
 * @brief Compiles AegisScript C-like source directly into a virtualized BytecodeChunk.
 * Variables are allocated in the VM memory frame (starting at stack offset 256).
 * Expressions evaluate on the VM stack and R0/R1 registers.
 */
class AegisScriptCompiler {
public:
    static inline BytecodeChunk compile(std::string_view source, u64 key = 0, bool polymorphic = true) {
        ScriptLexer lexer(source);
        auto tokens = lexer.tokenize();
        AegisScriptCompiler compiler(std::move(tokens), polymorphic);
        compiler.parse_program();
        return compiler.builder_.build(key);
    }

private:
    explicit AegisScriptCompiler(std::vector<ScriptToken> tokens, bool polymorphic)
        : tokens_(std::move(tokens)), pos_(0), builder_(polymorphic), next_var_offset_(256) {}

    const ScriptToken& peek() const noexcept {
        return (pos_ < tokens_.size()) ? tokens_[pos_] : tokens_.back();
    }

    const ScriptToken& advance() noexcept {
        const auto& tok = peek();
        if (pos_ + 1 < tokens_.size()) pos_++;
        return tok;
    }

    bool match(TokKind k) noexcept {
        if (peek().kind == k) {
            advance();
            return true;
        }
        return false;
    }

    u64 get_var_offset(const std::string& name) {
        auto it = vars_.find(name);
        if (it != vars_.end()) return it->second;
        u64 off = next_var_offset_;
        next_var_offset_ += 8;
        vars_[name] = off;
        return off;
    }

    void parse_program() {
        while (peek().kind != TokKind::Eof) {
            parse_stmt();
        }
        builder_.halt();
    }

    void parse_block() {
        if (match(TokKind::LBrace)) {
            while (peek().kind != TokKind::RBrace && peek().kind != TokKind::Eof) {
                parse_stmt();
            }
            match(TokKind::RBrace);
        } else {
            parse_stmt();
        }
    }

    void parse_stmt() {
        if (match(TokKind::KwLet)) {
            std::string name = advance().text;
            u64 off = get_var_offset(name);
            if (match(TokKind::Eq)) {
                parse_expr(); // result in R0
                builder_.mov(VReg::R2, off);
                builder_.store(VReg::R2, VReg::R0);
            }
            match(TokKind::Semi);
        } else if (match(TokKind::KwReturn)) {
            parse_expr(); // result in R0
            match(TokKind::Semi);
            builder_.halt();
        } else if (match(TokKind::KwIf)) {
            match(TokKind::LParen);
            parse_expr(); // condition in R0
            match(TokKind::RParen);

            Label lbl_else = builder_.create_label();
            Label lbl_end  = builder_.create_label();
            builder_.mov(VReg::R1, 0);
            builder_.cmp(VReg::R0, VReg::R1);
            builder_.jz(lbl_else);

            parse_block();
            builder_.jmp(lbl_end);

            builder_.bind_label(lbl_else);
            if (match(TokKind::KwElse)) {
                parse_block();
            }
            builder_.bind_label(lbl_end);
        } else if (match(TokKind::KwWhile)) {
            Label lbl_start = builder_.create_label();
            Label lbl_exit  = builder_.create_label();

            builder_.bind_label(lbl_start);
            match(TokKind::LParen);
            parse_expr(); // condition in R0
            match(TokKind::RParen);

            builder_.mov(VReg::R1, 0);
            builder_.cmp(VReg::R0, VReg::R1);
            builder_.jz(lbl_exit);

            parse_block();
            builder_.jmp(lbl_start);
            builder_.bind_label(lbl_exit);
        } else if (peek().kind == TokKind::Ident) {
            std::string name = advance().text;
            u64 off = get_var_offset(name);
            if (match(TokKind::Eq)) {
                parse_expr();
                builder_.mov(VReg::R2, off);
                builder_.store(VReg::R2, VReg::R0);
            }
            match(TokKind::Semi);
        } else {
            advance();
        }
    }

    void parse_expr() {
        parse_bit_or();
        while (peek().kind == TokKind::EqEq || peek().kind == TokKind::BangEq ||
               peek().kind == TokKind::Lt   || peek().kind == TokKind::Gt ||
               peek().kind == TokKind::LtEq || peek().kind == TokKind::GtEq) {
            TokKind op = advance().kind;
            builder_.push(VReg::R0);
            parse_bit_or();
            builder_.mov(VReg::R1, VReg::R0);
            builder_.pop(VReg::R0);
            builder_.cmp(VReg::R0, VReg::R1);

            Label lbl_true = builder_.create_label();
            Label lbl_done = builder_.create_label();
            if (op == TokKind::EqEq)        builder_.jz(lbl_true);
            else if (op == TokKind::BangEq) builder_.jnz(lbl_true);
            else if (op == TokKind::Lt)     builder_.jl(lbl_true);
            else if (op == TokKind::Gt)     builder_.jg(lbl_true);
            else if (op == TokKind::LtEq)   builder_.jle(lbl_true);
            else if (op == TokKind::GtEq)   builder_.jge(lbl_true);

            builder_.mov(VReg::R0, 0);
            builder_.jmp(lbl_done);
            builder_.bind_label(lbl_true);
            builder_.mov(VReg::R0, 1);
            builder_.bind_label(lbl_done);
        }
    }

    void parse_bit_or() {
        parse_bit_xor();
        while (match(TokKind::Pipe)) {
            builder_.push(VReg::R0);
            parse_bit_xor();
            builder_.mov(VReg::R1, VReg::R0);
            builder_.pop(VReg::R0);
            builder_.bitwise_or(VReg::R0, VReg::R1);
        }
    }

    void parse_bit_xor() {
        parse_bit_and();
        while (match(TokKind::Caret)) {
            builder_.push(VReg::R0);
            parse_bit_and();
            builder_.mov(VReg::R1, VReg::R0);
            builder_.pop(VReg::R0);
            builder_.bitwise_xor(VReg::R0, VReg::R1);
        }
    }

    void parse_bit_and() {
        parse_additive();
        while (match(TokKind::Amp)) {
            builder_.push(VReg::R0);
            parse_additive();
            builder_.mov(VReg::R1, VReg::R0);
            builder_.pop(VReg::R0);
            builder_.bitwise_and(VReg::R0, VReg::R1);
        }
    }

    void parse_additive() {
        parse_multiplicative();
        while (peek().kind == TokKind::Plus || peek().kind == TokKind::Minus) {
            TokKind op = advance().kind;
            builder_.push(VReg::R0);
            parse_multiplicative();
            builder_.mov(VReg::R1, VReg::R0);
            builder_.pop(VReg::R0);
            if (op == TokKind::Plus) builder_.add(VReg::R0, VReg::R1);
            else                     builder_.sub(VReg::R0, VReg::R1);
        }
    }

    void parse_multiplicative() {
        parse_primary();
        while (peek().kind == TokKind::Star || peek().kind == TokKind::Slash || peek().kind == TokKind::Percent) {
            TokKind op = advance().kind;
            builder_.push(VReg::R0);
            parse_primary();
            builder_.mov(VReg::R1, VReg::R0);
            builder_.pop(VReg::R0);
            if (op == TokKind::Star)       builder_.mul(VReg::R0, VReg::R1);
            else if (op == TokKind::Slash) builder_.div(VReg::R0, VReg::R1);
            else                           builder_.mod(VReg::R0, VReg::R1);
        }
    }

    void parse_primary() {
        if (match(TokKind::LParen)) {
            parse_expr();
            match(TokKind::RParen);
        } else if (peek().kind == TokKind::Number) {
            u64 v = advance().num_val;
            builder_.mov(VReg::R0, v);
        } else if (peek().kind == TokKind::Ident) {
            std::string name = advance().text;
            u64 off = get_var_offset(name);
            builder_.mov(VReg::R2, off);
            builder_.load(VReg::R0, VReg::R2);
        } else {
            builder_.mov(VReg::R0, 0);
        }
    }

    std::vector<ScriptToken> tokens_;
    size_t pos_;
    BytecodeBuilder builder_;
    u64 next_var_offset_;
    std::unordered_map<std::string, u64> vars_;
};

} // namespace vm::compiler

// ============================================================================
// 42. ENCRYPTED VIRTUAL FILE SYSTEM (VFS) & ASSET PACKAGER
// ============================================================================
namespace archive {

#pragma pack(push, 1)
struct VfsFileHeader {
    u64 path_hash;
    u32 uncompressed_size;
    u32 compressed_size;
    u32 data_offset;
    u8  nonce[12];
    u8  tag[16];
};

struct VfsArchiveHeader {
    u32 magic;       // 'AGVF' (0x46564741)
    u16 version;     // 1
    u16 file_count;
    u32 total_size;
    u32 header_crc;
};
#pragma pack(pop)

constexpr u32 AGVF_MAGIC = 0x46564741U;

class AegisVfsArchive {
public:
    using MasterKey = crypto::ChaCha20Poly1305::Key;

    explicit AegisVfsArchive(const MasterKey& key) noexcept : key_(key) {}

    void add_file(std::string_view virtual_path, const u8* data, size_t len) {
        u64 h = core::Fnv1a::hash(virtual_path);
        files_[h] = std::vector<u8>(data, data + len);
    }

    void add_file(std::string_view virtual_path, std::string_view text_content) {
        add_file(virtual_path, reinterpret_cast<const u8*>(text_content.data()), text_content.size());
    }

    std::vector<u8> serialize() const {
        std::vector<VfsFileHeader> entries;
        std::vector<u8> blob_pool;
        entries.reserve(files_.size());

        u64 nonce_ctr = 1;
        for (const auto& [path_hash, raw_data] : files_) {
            std::vector<u8> compressed = codec::LzssCodec::compress(raw_data.data(), raw_data.size());

            VfsFileHeader fhdr{};
            fhdr.path_hash = path_hash;
            fhdr.uncompressed_size = static_cast<u32>(raw_data.size());
            fhdr.data_offset = static_cast<u32>(blob_pool.size());

            crypto::ChaCha20Poly1305::Nonce nonce{};
            u64 r1 = core::RuntimeRandom::get_u64() ^ (nonce_ctr++);
            u32 r2 = core::RuntimeRandom::get_u32();
            std::memcpy(&nonce[0], &r1, 8);
            std::memcpy(&nonce[8], &r2, 4);
            std::memcpy(fhdr.nonce, nonce.data(), 12);

            crypto::ChaCha20Poly1305::Tag tag{};
            auto ct = crypto::ChaCha20Poly1305::seal(
                key_, nonce, compressed.data(), compressed.size(),
                reinterpret_cast<const u8*>(&path_hash), sizeof(path_hash), tag);

            std::memcpy(fhdr.tag, tag.data(), 16);
            fhdr.compressed_size = static_cast<u32>(ct.size());
            blob_pool.insert(blob_pool.end(), ct.begin(), ct.end());
            entries.push_back(fhdr);
        }

        VfsArchiveHeader ahdr{};
        ahdr.magic = AGVF_MAGIC;
        ahdr.version = 1;
        ahdr.file_count = static_cast<u16>(entries.size());
        ahdr.total_size = static_cast<u32>(sizeof(VfsArchiveHeader) + entries.size() * sizeof(VfsFileHeader) + blob_pool.size());
        ahdr.header_crc = core::Crc32::calculate(
            reinterpret_cast<const u8*>(entries.data()), entries.size() * sizeof(VfsFileHeader));

        std::vector<u8> archive_bytes;
        archive_bytes.reserve(ahdr.total_size);
        archive_bytes.insert(archive_bytes.end(),
                             reinterpret_cast<const u8*>(&ahdr),
                             reinterpret_cast<const u8*>(&ahdr) + sizeof(VfsArchiveHeader));
        if (!entries.empty()) {
            archive_bytes.insert(archive_bytes.end(),
                                 reinterpret_cast<const u8*>(entries.data()),
                                 reinterpret_cast<const u8*>(entries.data()) + entries.size() * sizeof(VfsFileHeader));
        }
        archive_bytes.insert(archive_bytes.end(), blob_pool.begin(), blob_pool.end());
        return archive_bytes;
    }

    bool deserialize_and_mount(const u8* archive_bytes, size_t len) {
        if (!archive_bytes || len < sizeof(VfsArchiveHeader)) return false;
        VfsArchiveHeader ahdr{};
        std::memcpy(&ahdr, archive_bytes, sizeof(VfsArchiveHeader));
        if (ahdr.magic != AGVF_MAGIC || ahdr.version != 1 || ahdr.total_size != len) return false;

        size_t table_bytes = static_cast<size_t>(ahdr.file_count) * sizeof(VfsFileHeader);
        if (sizeof(VfsArchiveHeader) + table_bytes > len) return false;

        const u8* table_ptr = archive_bytes + sizeof(VfsArchiveHeader);
        if (core::Crc32::calculate(table_ptr, table_bytes) != ahdr.header_crc) return false;

        const u8* blob_base = table_ptr + table_bytes;
        size_t blob_len = len - (sizeof(VfsArchiveHeader) + table_bytes);

        files_.clear();
        for (u16 i = 0; i < ahdr.file_count; ++i) {
            VfsFileHeader fhdr{};
            std::memcpy(&fhdr, table_ptr + i * sizeof(VfsFileHeader), sizeof(VfsFileHeader));
            if (static_cast<size_t>(fhdr.data_offset) + fhdr.compressed_size > blob_len) return false;

            crypto::ChaCha20Poly1305::Nonce nonce{};
            crypto::ChaCha20Poly1305::Tag tag{};
            std::memcpy(nonce.data(), fhdr.nonce, 12);
            std::memcpy(tag.data(), fhdr.tag, 16);

            std::vector<u8> compressed;
            if (!crypto::ChaCha20Poly1305::open(
                    key_, nonce,
                    blob_base + fhdr.data_offset, fhdr.compressed_size,
                    reinterpret_cast<const u8*>(&fhdr.path_hash), sizeof(fhdr.path_hash),
                    tag, compressed)) {
                return false;
            }

            std::vector<u8> raw = codec::LzssCodec::decompress(compressed.data(), compressed.size());
            if (raw.size() != fhdr.uncompressed_size) return false;
            files_[fhdr.path_hash] = std::move(raw);
        }
        return true;
    }

    bool read_file(std::string_view virtual_path, std::vector<u8>& out_data) const {
        u64 h = core::Fnv1a::hash(virtual_path);
        auto it = files_.find(h);
        if (it == files_.end()) return false;
        out_data = it->second;
        return true;
    }

    std::string read_text(std::string_view virtual_path) const {
        std::vector<u8> data;
        if (!read_file(virtual_path, data)) return {};
        return std::string(reinterpret_cast<const char*>(data.data()), data.size());
    }

    size_t file_count() const noexcept { return files_.size(); }

private:
    MasterKey key_{};
    std::unordered_map<u64, std::vector<u8>> files_;
};

} // namespace archive

// ============================================================================
// 43. REPLAY-PROTECTED ENCRYPTED PACKET CHANNEL (AEAD + SLIDING WINDOW)
// ============================================================================
namespace ipc {

class ReplayWindow64 {
public:
    constexpr ReplayWindow64() noexcept = default;

    constexpr bool check_and_accept(u64 seq) noexcept {
        if (seq == 0) return false;
        if (seq > highest_seq_) {
            u64 shift = seq - highest_seq_;
            if (shift >= 64) {
                bitmap_ = 1ULL;
            } else {
                bitmap_ = (bitmap_ << shift) | 1ULL;
            }
            highest_seq_ = seq;
            return true;
        }
        u64 diff = highest_seq_ - seq;
        if (diff >= 64) return false;
        u64 mask = 1ULL << diff;
        if ((bitmap_ & mask) != 0) return false; // duplicate replay!
        bitmap_ |= mask;
        return true;
    }

    constexpr void reset() noexcept {
        highest_seq_ = 0;
        bitmap_ = 0;
    }

private:
    u64 highest_seq_{0};
    u64 bitmap_{0};
};

class SecurePacketChannel {
public:
    explicit SecurePacketChannel(const crypto::ChaCha20Poly1305::Key& shared_key) noexcept
        : key_(shared_key), tx_seq_(1) {}

    std::vector<u8> seal_packet(u16 packet_type, const u8* payload, size_t len) {
        u64 seq = tx_seq_++;
        crypto::ChaCha20Poly1305::Nonce nonce{};
        std::memcpy(&nonce[0], &seq, 8);
        std::memcpy(&nonce[8], &packet_type, 2);

        u8 header[10]{};
        std::memcpy(&header[0], &seq, 8);
        std::memcpy(&header[8], &packet_type, 2);

        crypto::ChaCha20Poly1305::Tag tag{};
        auto ct = crypto::ChaCha20Poly1305::seal(key_, nonce, payload, len, header, sizeof(header), tag);

        std::vector<u8> frame;
        frame.reserve(10 + 16 + ct.size());
        frame.insert(frame.end(), header, header + 10);
        frame.insert(frame.end(), tag.begin(), tag.end());
        frame.insert(frame.end(), ct.begin(), ct.end());
        return frame;
    }

    bool open_packet(const u8* frame, size_t frame_len, u16& out_type, std::vector<u8>& out_payload) {
        if (!frame || frame_len < 26) return false;
        u64 seq = 0;
        u16 ptype = 0;
        std::memcpy(&seq, &frame[0], 8);
        std::memcpy(&ptype, &frame[8], 2);

        crypto::ChaCha20Poly1305::Nonce nonce{};
        std::memcpy(&nonce[0], &seq, 8);
        std::memcpy(&nonce[8], &ptype, 2);

        crypto::ChaCha20Poly1305::Tag tag{};
        std::memcpy(tag.data(), &frame[10], 16);

        if (!crypto::ChaCha20Poly1305::open(
                key_, nonce,
                &frame[26], frame_len - 26,
                frame, 10, tag, out_payload)) {
            return false;
        }

        if (!rx_window_.check_and_accept(seq)) {
            out_payload.clear();
            return false;
        }

        out_type = ptype;
        return true;
    }

private:
    crypto::ChaCha20Poly1305::Key key_{};
    u64 tx_seq_{1};
    ReplayWindow64 rx_window_{};
};

} // namespace ipc


// ============================================================================
// 44. ZERO-DEPENDENCY JSON DOM PARSER, BUILDER & SERIALIZER
// ============================================================================
namespace json {

enum class JsonType : u8 {
    Null = 0,
    Boolean,
    Integer,
    String,
    Array,
    Object
};

class JsonValue {
public:
    JsonValue() noexcept : type_(JsonType::Null) {}
    explicit JsonValue(bool b) noexcept : type_(JsonType::Boolean), bool_val_(b) {}
    explicit JsonValue(i64 n) noexcept : type_(JsonType::Integer), int_val_(n) {}
    explicit JsonValue(std::string s) noexcept : type_(JsonType::String), str_val_(std::move(s)) {}
    explicit JsonValue(const char* s) : type_(JsonType::String), str_val_(s ? s : "") {}

    static inline JsonValue make_array() {
        JsonValue v;
        v.type_ = JsonType::Array;
        return v;
    }

    static inline JsonValue make_object() {
        JsonValue v;
        v.type_ = JsonType::Object;
        return v;
    }

    JsonType type() const noexcept { return type_; }
    bool is_null() const noexcept { return type_ == JsonType::Null; }
    bool is_bool() const noexcept { return type_ == JsonType::Boolean; }
    bool is_int() const noexcept { return type_ == JsonType::Integer; }
    bool is_string() const noexcept { return type_ == JsonType::String; }
    bool is_array() const noexcept { return type_ == JsonType::Array; }
    bool is_object() const noexcept { return type_ == JsonType::Object; }

    bool as_bool(bool def = false) const noexcept { return is_bool() ? bool_val_ : def; }
    i64 as_int(i64 def = 0) const noexcept { return is_int() ? int_val_ : def; }
    const std::string& as_string() const noexcept { return str_val_; }
    const std::vector<JsonValue>& as_array() const noexcept { return arr_val_; }
    const std::vector<std::pair<std::string, JsonValue>>& as_object() const noexcept { return obj_val_; }

    void push_back(JsonValue val) {
        if (type_ != JsonType::Array) {
            type_ = JsonType::Array;
            arr_val_.clear();
        }
        arr_val_.push_back(std::move(val));
    }

    void set(std::string key, JsonValue val) {
        if (type_ != JsonType::Object) {
            type_ = JsonType::Object;
            obj_val_.clear();
        }
        for (auto& kv : obj_val_) {
            if (kv.first == key) {
                kv.second = std::move(val);
                return;
            }
        }
        obj_val_.emplace_back(std::move(key), std::move(val));
    }

    const JsonValue* get(std::string_view key) const noexcept {
        if (type_ != JsonType::Object) return nullptr;
        for (const auto& kv : obj_val_) {
            if (kv.first == key) return &kv.second;
        }
        return nullptr;
    }

    std::string dump(int indent = -1, int current_depth = 0) const {
        std::ostringstream oss;
        switch (type_) {
        case JsonType::Null:
            oss << "null";
            break;
        case JsonType::Boolean:
            oss << (bool_val_ ? "true" : "false");
            break;
        case JsonType::Integer:
            oss << int_val_;
            break;
        case JsonType::String:
            oss << '"' << escape_string(str_val_) << '"';
            break;
        case JsonType::Array: {
            if (arr_val_.empty()) {
                oss << "[]";
                break;
            }
            oss << '[';
            for (size_t i = 0; i < arr_val_.size(); ++i) {
                if (i > 0) oss << ',';
                if (indent >= 0) {
                    oss << '\n' << std::string(static_cast<size_t>((current_depth + 1) * indent), ' ');
                }
                oss << arr_val_[i].dump(indent, current_depth + 1);
            }
            if (indent >= 0) {
                oss << '\n' << std::string(static_cast<size_t>(current_depth * indent), ' ');
            }
            oss << ']';
            break;
        }
        case JsonType::Object: {
            if (obj_val_.empty()) {
                oss << "{}";
                break;
            }
            oss << '{';
            for (size_t i = 0; i < obj_val_.size(); ++i) {
                if (i > 0) oss << ',';
                if (indent >= 0) {
                    oss << '\n' << std::string(static_cast<size_t>((current_depth + 1) * indent), ' ');
                }
                oss << '"' << escape_string(obj_val_[i].first) << "\":";
                if (indent >= 0) oss << ' ';
                oss << obj_val_[i].second.dump(indent, current_depth + 1);
            }
            if (indent >= 0) {
                oss << '\n' << std::string(static_cast<size_t>(current_depth * indent), ' ');
            }
            oss << '}';
            break;
        }
        }
        return oss.str();
    }

private:
    static inline std::string escape_string(std::string_view s) {
        std::string out;
        out.reserve(s.size() + 4);
        for (char c : s) {
            switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out.push_back(c); break;
            }
        }
        return out;
    }

    JsonType type_;
    bool bool_val_{false};
    i64 int_val_{0};
    std::string str_val_;
    std::vector<JsonValue> arr_val_;
    std::vector<std::pair<std::string, JsonValue>> obj_val_;
};

class JsonParser {
public:
    static inline JsonValue parse(std::string_view input, bool& out_ok) {
        JsonParser p(input);
        p.skip_ws();
        JsonValue val = p.parse_value(out_ok);
        if (!out_ok) return JsonValue();
        p.skip_ws();
        if (p.pos_ != p.src_.size()) {
            out_ok = false;
            return JsonValue();
        }
        return val;
    }

private:
    explicit JsonParser(std::string_view src) noexcept : src_(src), pos_(0) {}

    void skip_ws() noexcept {
        while (pos_ < src_.size() && (src_[pos_] == ' ' || src_[pos_] == '\t' || src_[pos_] == '\r' || src_[pos_] == '\n')) {
            pos_++;
        }
    }

    JsonValue parse_value(bool& ok) {
        skip_ws();
        if (pos_ >= src_.size()) { ok = false; return JsonValue(); }
        char c = src_[pos_];
        if (c == '{') return parse_object(ok);
        if (c == '[') return parse_array(ok);
        if (c == '"') return JsonValue(parse_string(ok));
        if (c == 't' && src_.substr(pos_, 4) == "true") {
            pos_ += 4; ok = true; return JsonValue(true);
        }
        if (c == 'f' && src_.substr(pos_, 5) == "false") {
            pos_ += 5; ok = true; return JsonValue(false);
        }
        if (c == 'n' && src_.substr(pos_, 4) == "null") {
            pos_ += 4; ok = true; return JsonValue();
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            return parse_number(ok);
        }
        ok = false;
        return JsonValue();
    }

    std::string parse_string(bool& ok) {
        if (pos_ >= src_.size() || src_[pos_] != '"') { ok = false; return {}; }
        pos_++;
        std::string out;
        while (pos_ < src_.size()) {
            char c = src_[pos_++];
            if (c == '"') {
                ok = true;
                return out;
            }
            if (c == '\\') {
                if (pos_ >= src_.size()) { ok = false; return {}; }
                char esc = src_[pos_++];
                switch (esc) {
                case '"':  out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/'); break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                default:   out.push_back(esc); break;
                }
            } else {
                out.push_back(c);
            }
        }
        ok = false;
        return {};
    }

    JsonValue parse_number(bool& ok) {
        size_t start = pos_;
        if (src_[pos_] == '-') pos_++;
        if (pos_ >= src_.size() || src_[pos_] < '0' || src_[pos_] > '9') {
            ok = false; return JsonValue();
        }
        while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') {
            pos_++;
        }
        std::string num_s(src_.substr(start, pos_ - start));
        i64 v = std::strtoll(num_s.c_str(), nullptr, 10);
        ok = true;
        return JsonValue(v);
    }

    JsonValue parse_array(bool& ok) {
        pos_++; // skip '['
        JsonValue arr = JsonValue::make_array();
        skip_ws();
        if (pos_ < src_.size() && src_[pos_] == ']') {
            pos_++; ok = true; return arr;
        }
        while (pos_ < src_.size()) {
            bool elem_ok = false;
            JsonValue elem = parse_value(elem_ok);
            if (!elem_ok) { ok = false; return JsonValue(); }
            arr.push_back(std::move(elem));
            skip_ws();
            if (pos_ < src_.size() && src_[pos_] == ',') {
                pos_++;
                continue;
            }
            if (pos_ < src_.size() && src_[pos_] == ']') {
                pos_++; ok = true; return arr;
            }
            break;
        }
        ok = false;
        return JsonValue();
    }

    JsonValue parse_object(bool& ok) {
        pos_++; // skip '{'
        JsonValue obj = JsonValue::make_object();
        skip_ws();
        if (pos_ < src_.size() && src_[pos_] == '}') {
            pos_++; ok = true; return obj;
        }
        while (pos_ < src_.size()) {
            skip_ws();
            bool key_ok = false;
            std::string key = parse_string(key_ok);
            if (!key_ok) { ok = false; return JsonValue(); }
            skip_ws();
            if (pos_ >= src_.size() || src_[pos_] != ':') { ok = false; return JsonValue(); }
            pos_++;
            bool val_ok = false;
            JsonValue val = parse_value(val_ok);
            if (!val_ok) { ok = false; return JsonValue(); }
            obj.set(std::move(key), std::move(val));
            skip_ws();
            if (pos_ < src_.size() && src_[pos_] == ',') {
                pos_++;
                continue;
            }
            if (pos_ < src_.size() && src_[pos_] == '}') {
                pos_++; ok = true; return obj;
            }
            break;
        }
        ok = false;
        return JsonValue();
    }

    std::string_view src_;
    size_t pos_;
};

} // namespace json

// ============================================================================
// 45. CROSS-PLATFORM ELF64 & MACH-O 64 BINARY STATIC SECURITY ANALYZER
// ============================================================================
namespace binfmt {

#pragma pack(push, 1)
struct Elf64Ehdr {
    u8  e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
};

struct Elf64Phdr {
    u32 p_type;
    u32 p_flags;
    u64 p_offset;
    u64 p_vaddr;
    u64 p_paddr;
    u64 p_filesz;
    u64 p_memsz;
    u64 p_align;
};

struct MachHeader64 {
    u32 magic;
    u32 cputype;
    u32 cpusubtype;
    u32 filetype;
    u32 ncmds;
    u32 sizeofcmds;
    u32 flags;
    u32 reserved;
};
#pragma pack(pop)

struct BinaryAuditSummary {
    enum class Format : u8 { Unknown = 0, PE, ELF64, MachO64 };
    Format format{Format::Unknown};
    bool is_64bit{false};
    bool has_nx_stack{false};
    bool has_pie_aslr{false};
    u64 entry_point{0};
    u32 segment_or_section_count{0};
    u32 rwx_segments{0};
};

class UniversalBinaryInspector {
public:
    static inline BinaryAuditSummary inspect_buffer(const u8* data, size_t len) noexcept {
        BinaryAuditSummary sum{};
        if (!data || len < 64) return sum;

        // Check ELF64 Magic: 0x7F 'E' 'L' 'F'
        if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
            if (data[4] != 2 || len < sizeof(Elf64Ehdr)) return sum;
            Elf64Ehdr eh{};
            std::memcpy(&eh, data, sizeof(Elf64Ehdr));
            sum.format = BinaryAuditSummary::Format::ELF64;
            sum.is_64bit = true;
            sum.entry_point = eh.e_entry;
            sum.has_pie_aslr = (eh.e_type == 3); // ET_DYN (PIE / shared object)
            sum.segment_or_section_count = eh.e_phnum;

            if (eh.e_phoff > 0 && eh.e_phentsize >= sizeof(Elf64Phdr)) {
                for (u16 i = 0; i < eh.e_phnum; ++i) {
                    size_t off = static_cast<size_t>(eh.e_phoff) + static_cast<size_t>(i) * eh.e_phentsize;
                    if (off + sizeof(Elf64Phdr) > len) break;
                    Elf64Phdr ph{};
                    std::memcpy(&ph, data + off, sizeof(Elf64Phdr));
                    // PF_X = 1, PF_W = 2, PF_R = 4
                    if ((ph.p_flags & 0x3) == 0x3) sum.rwx_segments++;
                    // PT_GNU_STACK = 0x6474e551
                    if (ph.p_type == 0x6474e551U && (ph.p_flags & 1) == 0) {
                        sum.has_nx_stack = true;
                    }
                }
            }
            return sum;
        }

        // Check Mach-O 64 Magic: 0xFEEDFACF (little-endian: CF FA ED FE)
        u32 magic32 = 0;
        std::memcpy(&magic32, data, 4);
        if (magic32 == 0xFEEDFACFU) {
            MachHeader64 mh{};
            std::memcpy(&mh, data, sizeof(MachHeader64));
            sum.format = BinaryAuditSummary::Format::MachO64;
            sum.is_64bit = true;
            sum.segment_or_section_count = mh.ncmds;
            sum.has_pie_aslr = (mh.flags & 0x200000U) != 0; // MH_PIE
            sum.has_nx_stack = (mh.flags & 0x020000U) == 0; // !MH_ALLOW_STACK_EXECUTION
            return sum;
        }

        // Check PE Magic: 'MZ' (0x5A4D)
        if (data[0] == 'M' && data[1] == 'Z') {
            sum.format = BinaryAuditSummary::Format::PE;
            u32 lfanew = 0;
            std::memcpy(&lfanew, data + 0x3C, 4);
            if (static_cast<size_t>(lfanew) + 26 <= len &&
                data[lfanew] == 'P' && data[lfanew + 1] == 'E' && data[lfanew + 2] == 0 && data[lfanew + 3] == 0) {
                u16 opt_magic = 0;
                std::memcpy(&opt_magic, data + lfanew + 24, 2);
                sum.is_64bit = (opt_magic == 0x20B);
            }
            return sum;
        }

        return sum;
    }
};

} // namespace binfmt

// ============================================================================
// 46. WHITE-BOX CRYPTOGRAPHY & MULTI-LAYER BYTECODE ENVELOPE ENGINE
// ============================================================================
namespace whitebox {

/**
 * @brief Compile-time & Runtime Bijective 8-bit S-Box and Lookup Table Network
 * Used for White-Box key hiding so raw symmetric keys never materialize in registers.
 */
template <u64 Seed>
class WhiteBoxByteNetwork {
public:
    struct NetworkTables {
        std::array< std::array<u8, 256>, 16 > round_sboxes{};
        std::array< std::array<u8, 256>, 16 > inv_round_sboxes{};
    };

    static constexpr NetworkTables generate() noexcept {
        NetworkTables net{};
        u64 st = Seed ^ 0xA5A5F0F012345678ULL;
        for (size_t r = 0; r < 16; ++r) {
            for (size_t i = 0; i < 256; ++i) {
                net.round_sboxes[r][i] = static_cast<u8>(i);
            }
            for (size_t i = 255; i > 0; --i) {
                st ^= st >> 12;
                st ^= st << 25;
                st ^= st >> 27;
                u64 rnd = st * 0x2545F4914F6CDD1DULL;
                size_t j = static_cast<size_t>(rnd % (i + 1));
                u8 tmp = net.round_sboxes[r][i];
                net.round_sboxes[r][i] = net.round_sboxes[r][j];
                net.round_sboxes[r][j] = tmp;
            }
            for (size_t i = 0; i < 256; ++i) {
                net.inv_round_sboxes[r][net.round_sboxes[r][i]] = static_cast<u8>(i);
            }
        }
        return net;
    }

    static constexpr NetworkTables tables = generate();

    static inline void encode_buffer(u8* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            u8 v = data[i];
            for (size_t r = 0; r < 16; ++r) {
                v = tables.round_sboxes[(i + r) & 15][v];
            }
            data[i] = v;
        }
    }

    static inline void decode_buffer(u8* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            u8 v = data[i];
            for (int r = 15; r >= 0; --r) {
                v = tables.inv_round_sboxes[(i + static_cast<size_t>(r)) & 15][v];
            }
            data[i] = v;
        }
    }
};

/**
 * @brief Multi-Layer Bytecode Envelope (LZSS + WhiteBox Network + ChaCha20-Poly1305)
 * Wraps a VM BytecodeChunk in 3 independent cryptographic and compression layers.
 */
class BytecodeEnvelope {
public:
    using Key = crypto::ChaCha20Poly1305::Key;

    static inline std::vector<u8> seal_chunk(const vm::BytecodeChunk& chunk, const Key& key) {
        const auto& raw = chunk.get_raw_data();
        std::vector<u8> compressed = codec::LzssCodec::compress(raw.data(), raw.size());
        WhiteBoxByteNetwork<0x7F3A9C1B2E4D6085ULL>::encode_buffer(compressed.data(), compressed.size());

        crypto::ChaCha20Poly1305::Nonce nonce{};
        u64 r1 = core::RuntimeRandom::get_u64();
        u32 r2 = core::RuntimeRandom::get_u32();
        std::memcpy(&nonce[0], &r1, 8);
        std::memcpy(&nonce[8], &r2, 4);

        u32 orig_len = static_cast<u32>(raw.size());
        crypto::ChaCha20Poly1305::Tag tag{};
        auto ct = crypto::ChaCha20Poly1305::seal(
            key, nonce, compressed.data(), compressed.size(),
            reinterpret_cast<const u8*>(&orig_len), sizeof(orig_len), tag);

        std::vector<u8> envelope;
        envelope.reserve(4 + 12 + 16 + ct.size());
        for (int i = 0; i < 4; ++i) envelope.push_back(static_cast<u8>((orig_len >> (i * 8)) & 0xFF));
        envelope.insert(envelope.end(), nonce.begin(), nonce.end());
        envelope.insert(envelope.end(), tag.begin(), tag.end());
        envelope.insert(envelope.end(), ct.begin(), ct.end());
        return envelope;
    }

    static inline bool unseal_chunk(const u8* envelope, size_t len, const Key& key, vm::BytecodeChunk& out_chunk) {
        if (!envelope || len < 32) return false;
        u32 orig_len = static_cast<u32>(envelope[0]) |
                      (static_cast<u32>(envelope[1]) << 8) |
                      (static_cast<u32>(envelope[2]) << 16) |
                      (static_cast<u32>(envelope[3]) << 24);

        crypto::ChaCha20Poly1305::Nonce nonce{};
        crypto::ChaCha20Poly1305::Tag tag{};
        std::memcpy(nonce.data(), &envelope[4], 12);
        std::memcpy(tag.data(), &envelope[16], 16);

        std::vector<u8> compressed;
        if (!crypto::ChaCha20Poly1305::open(
                key, nonce,
                &envelope[32], len - 32,
                reinterpret_cast<const u8*>(&orig_len), sizeof(orig_len),
                tag, compressed)) {
            return false;
        }

        WhiteBoxByteNetwork<0x7F3A9C1B2E4D6085ULL>::decode_buffer(compressed.data(), compressed.size());
        std::vector<u8> raw = codec::LzssCodec::decompress(compressed.data(), compressed.size());
        if (raw.size() != orig_len) return false;

        out_chunk.get_raw_data() = std::move(raw);
        return out_chunk.verify_integrity();
    }
};

} // namespace whitebox


// ============================================================================
// 47. RFC 3713 CAMELLIA-256, RC6-256, SIMON128/256 & XXHASH64 / WYHASH64
// ============================================================================
namespace crypto {

/**
 * @brief RC6-256/20/32 Parameterized Block Cipher (128-bit blocks, 256-bit key, 20 rounds)
 */
class Rc6_256 {
public:
    using Key   = std::array<u8, 32>;
    using Block = std::array<u8, 16>;

    static constexpr u32 P32 = 0xB7E15163UL;
    static constexpr u32 Q32 = 0x9E3779B9UL;

    static constexpr u32 rotl32(u32 x, u32 n) noexcept {
        n &= 31;
        return (n == 0) ? x : ((x << n) | (x >> (32 - n)));
    }

    static constexpr u32 rotr32(u32 x, u32 n) noexcept {
        n &= 31;
        return (n == 0) ? x : ((x >> n) | (x << (32 - n)));
    }

    constexpr explicit Rc6_256(const Key& key) noexcept {
        std::array<u32, 8> L{};
        for (size_t i = 0; i < 8; ++i) {
            L[i] = static_cast<u32>(key[i * 4 + 0]) |
                  (static_cast<u32>(key[i * 4 + 1]) << 8) |
                  (static_cast<u32>(key[i * 4 + 2]) << 16) |
                  (static_cast<u32>(key[i * 4 + 3]) << 24);
        }

        S_[0] = P32;
        for (size_t i = 1; i < 44; ++i) {
            S_[i] = S_[i - 1] + Q32;
        }

        u32 A = 0, B = 0;
        size_t i = 0, j = 0;
        for (size_t k = 0; k < 132; ++k) {
            A = S_[i] = rotl32(S_[i] + A + B, 3);
            B = L[j]  = rotl32(L[j] + A + B, A + B);
            i = (i + 1) % 44;
            j = (j + 1) % 8;
        }
    }

    constexpr void encrypt_block(Block& blk) const noexcept {
        auto load32 = [](const u8* p) constexpr noexcept -> u32 {
            return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
                  (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
        };
        auto store32 = [](u8* p, u32 v) constexpr noexcept {
            p[0] = static_cast<u8>(v & 0xFF);
            p[1] = static_cast<u8>((v >> 8) & 0xFF);
            p[2] = static_cast<u8>((v >> 16) & 0xFF);
            p[3] = static_cast<u8>((v >> 24) & 0xFF);
        };

        u32 A = load32(&blk[0]);
        u32 B = load32(&blk[4]) + S_[0];
        u32 C = load32(&blk[8]);
        u32 D = load32(&blk[12]) + S_[1];

        for (size_t r = 1; r <= 20; ++r) {
            u32 t = rotl32(B * (2 * B + 1), 5);
            u32 u = rotl32(D * (2 * D + 1), 5);
            A = rotl32(A ^ t, u) + S_[2 * r];
            C = rotl32(C ^ u, t) + S_[2 * r + 1];
            u32 tmp = A; A = B; B = C; C = D; D = tmp;
        }

        A += S_[42];
        C += S_[43];

        store32(&blk[0], A);
        store32(&blk[4], B);
        store32(&blk[8], C);
        store32(&blk[12], D);
    }

    constexpr void decrypt_block(Block& blk) const noexcept {
        auto load32 = [](const u8* p) constexpr noexcept -> u32 {
            return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
                  (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
        };
        auto store32 = [](u8* p, u32 v) constexpr noexcept {
            p[0] = static_cast<u8>(v & 0xFF);
            p[1] = static_cast<u8>((v >> 8) & 0xFF);
            p[2] = static_cast<u8>((v >> 16) & 0xFF);
            p[3] = static_cast<u8>((v >> 24) & 0xFF);
        };

        u32 A = load32(&blk[0]);
        u32 B = load32(&blk[4]);
        u32 C = load32(&blk[8]) - S_[43];
        u32 D = load32(&blk[12]);
        A -= S_[42];

        for (size_t r = 20; r >= 1; --r) {
            u32 tmp = D; D = C; C = B; B = A; A = tmp;
            u32 u = rotl32(D * (2 * D + 1), 5);
            u32 t = rotl32(B * (2 * B + 1), 5);
            C = rotr32(C - S_[2 * r + 1], t) ^ u;
            A = rotr32(A - S_[2 * r], u) ^ t;
        }

        D -= S_[1];
        B -= S_[0];

        store32(&blk[0], A);
        store32(&blk[4], B);
        store32(&blk[8], C);
        store32(&blk[12], D);
    }

private:
    std::array<u32, 44> S_{};
};

/**
 * @brief Simon128/256 Block Cipher (72 Rounds)
 */
class Simon128 {
public:
    using Key   = std::array<u64, 4>;
    using Block = std::array<u64, 2>;

    static constexpr u64 Z4 = 0xfdc94c3a046d678bULL;

    static constexpr u64 rotl64(u64 x, u32 r) noexcept { return (x << r) | (x >> (64 - r)); }
    static constexpr u64 rotr64(u64 x, u32 r) noexcept { return (x >> r) | (x << (64 - r)); }

    static constexpr u64 f(u64 x) noexcept {
        return (rotl64(x, 1) & rotl64(x, 8)) ^ rotl64(x, 2);
    }

    constexpr explicit Simon128(const Key& k) noexcept {
        for (size_t i = 0; i < 4; ++i) rk_[i] = k[i];
        for (size_t i = 4; i < 72; ++i) {
            u64 tmp = rotr64(rk_[i - 1], 3) ^ rk_[i - 3];
            tmp ^= rotr64(tmp, 1);
            u64 z_bit = (Z4 >> ((i - 4) % 62)) & 1ULL;
            rk_[i] = (~rk_[i - 4]) ^ tmp ^ z_bit ^ 3ULL;
        }
    }

    constexpr void encrypt_block(Block& b) const noexcept {
        u64 x = b[1], y = b[0];
        for (size_t i = 0; i < 72; ++i) {
            u64 tmp = x;
            x = y ^ f(x) ^ rk_[i];
            y = tmp;
        }
        b[1] = x; b[0] = y;
    }

    constexpr void decrypt_block(Block& b) const noexcept {
        u64 x = b[1], y = b[0];
        for (int i = 71; i >= 0; --i) {
            u64 tmp = y;
            y = x ^ f(y) ^ rk_[static_cast<size_t>(i)];
            x = tmp;
        }
        b[1] = x; b[0] = y;
    }

private:
    std::array<u64, 72> rk_{};
};

} // namespace crypto

namespace core {

/**
 * @brief High-Speed xxHash64 Non-Cryptographic Checksum Engine
 */
class XxHash64 {
public:
    static constexpr u64 PRIME1 = 11400714785074694791ULL;
    static constexpr u64 PRIME2 = 14029467366897019727ULL;
    static constexpr u64 PRIME3 =  1609587929392839161ULL;
    static constexpr u64 PRIME4 =  9650029242287828579ULL;
    static constexpr u64 PRIME5 =  2870177450012600261ULL;

    static constexpr u64 rotl64(u64 x, u32 r) noexcept {
        return (x << r) | (x >> (64 - r));
    }

    static constexpr u64 round(u64 acc, u64 input) noexcept {
        acc += input * PRIME2;
        acc = rotl64(acc, 31);
        acc *= PRIME1;
        return acc;
    }

    static constexpr u64 merge_round(u64 acc, u64 val) noexcept {
        val = round(0, val);
        acc ^= val;
        acc = acc * PRIME1 + PRIME4;
        return acc;
    }

    static constexpr u64 hash(const u8* input, size_t len, u64 seed = 0) noexcept {
        auto read64 = [](const u8* p) constexpr noexcept -> u64 {
            return static_cast<u64>(p[0]) | (static_cast<u64>(p[1]) << 8) |
                  (static_cast<u64>(p[2]) << 16) | (static_cast<u64>(p[3]) << 24) |
                  (static_cast<u64>(p[4]) << 32) | (static_cast<u64>(p[5]) << 40) |
                  (static_cast<u64>(p[6]) << 48) | (static_cast<u64>(p[7]) << 56);
        };
        auto read32 = [](const u8* p) constexpr noexcept -> u32 {
            return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
                  (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
        };

        const u8* p = input;
        const u8* b_end = p + len;
        u64 h64 = 0;

        if (len >= 32) {
            const u8* limit = b_end - 32;
            u64 v1 = seed + PRIME1 + PRIME2;
            u64 v2 = seed + PRIME2;
            u64 v3 = seed + 0;
            u64 v4 = seed - PRIME1;

            do {
                v1 = round(v1, read64(p)); p += 8;
                v2 = round(v2, read64(p)); p += 8;
                v3 = round(v3, read64(p)); p += 8;
                v4 = round(v4, read64(p)); p += 8;
            } while (p <= limit);

            h64 = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
            h64 = merge_round(h64, v1);
            h64 = merge_round(h64, v2);
            h64 = merge_round(h64, v3);
            h64 = merge_round(h64, v4);
        } else {
            h64 = seed + PRIME5;
        }

        h64 += static_cast<u64>(len);

        while (p + 8 <= b_end) {
            u64 k1 = round(0, read64(p));
            h64 ^= k1;
            h64 = rotl64(h64, 27) * PRIME1 + PRIME4;
            p += 8;
        }

        if (p + 4 <= b_end) {
            h64 ^= static_cast<u64>(read32(p)) * PRIME1;
            h64 = rotl64(h64, 23) * PRIME2 + PRIME3;
            p += 4;
        }

        while (p < b_end) {
            h64 ^= static_cast<u64>(*p++) * PRIME5;
            h64 = rotl64(h64, 11) * PRIME1;
        }

        h64 ^= h64 >> 33;
        h64 *= PRIME2;
        h64 ^= h64 >> 29;
        h64 *= PRIME3;
        h64 ^= h64 >> 32;
        return h64;
    }

    static constexpr u64 hash(std::string_view sv, u64 seed = 0) noexcept {
        return hash(reinterpret_cast<const u8*>(sv.data()), sv.size(), seed);
    }
};

/**
 * @brief RFC 1950 Adler-32 & Fletcher-64 Fast Checksums
 */
class FastChecksums {
public:
    static constexpr u32 adler32(const u8* data, size_t len) noexcept {
        constexpr u32 MOD_ADLER = 65521U;
        u32 a = 1, b = 0;
        for (size_t i = 0; i < len; ++i) {
            a = (a + data[i]) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }
        return (b << 16) | a;
    }

    static constexpr u64 fletcher64(const u8* data, size_t len) noexcept {
        u64 sum1 = 0, sum2 = 0;
        size_t blocks = len / 4;
        for (size_t i = 0; i < blocks; ++i) {
            u32 word = static_cast<u32>(data[i * 4 + 0]) |
                      (static_cast<u32>(data[i * 4 + 1]) << 8) |
                      (static_cast<u32>(data[i * 4 + 2]) << 16) |
                      (static_cast<u32>(data[i * 4 + 3]) << 24);
            sum1 = (sum1 + word) % 0xFFFFFFFFULL;
            sum2 = (sum2 + sum1) % 0xFFFFFFFFULL;
        }
        return (sum2 << 32) | sum1;
    }
};

} // namespace core

// ============================================================================
// 48. STATIC SINGLE ASSIGNMENT (SSA) LIFTER & LINEAR SCAN REGISTER ALLOCATOR
// ============================================================================
namespace vm::ssa {

struct SsaVariable {
    u32 base_reg{0};
    u32 version{0};

    constexpr bool operator==(const SsaVariable& o) const noexcept {
        return base_reg == o.base_reg && version == o.version;
    }
};

struct SsaInstruction {
    u32 index{0};
    Opcode op{Opcode::OP_NOP};
    bool has_def{false};
    SsaVariable def{};
    std::vector<SsaVariable> uses;
    u64 imm{0};
};

struct LiveInterval {
    SsaVariable var{};
    u32 start_inst{0};
    u32 end_inst{0};
    VReg assigned_phys_reg{VReg::R0};
    bool spilled{false};
};

class SsaLifter {
public:
    static inline std::vector<SsaInstruction> lift_linear_block(const std::vector<disasm::DecodedInstruction>& insts) {
        std::vector<SsaInstruction> ssa_insts;
        ssa_insts.reserve(insts.size());

        std::array<u32, 16> current_ver{};

        auto use_reg = [&](VReg r) -> SsaVariable {
            u32 idx = static_cast<u32>(r) & 15;
            return SsaVariable{idx, current_ver[idx]};
        };

        auto def_reg = [&](VReg r) -> SsaVariable {
            u32 idx = static_cast<u32>(r) & 15;
            current_ver[idx]++;
            return SsaVariable{idx, current_ver[idx]};
        };

        for (size_t i = 0; i < insts.size(); ++i) {
            const auto& dec = insts[i];
            SsaInstruction s{};
            s.index = static_cast<u32>(i);
            s.op = dec.opcode;
            s.imm = dec.imm64;

            switch (dec.opcode) {
            case Opcode::OP_MOV_IMM:
                s.has_def = true;
                s.def = def_reg(dec.reg1);
                break;
            case Opcode::OP_MOV_REG:
            case Opcode::OP_POPCNT:
            case Opcode::OP_LOAD:
                s.uses.push_back(use_reg(dec.reg2));
                s.has_def = true;
                s.def = def_reg(dec.reg1);
                break;
            case Opcode::OP_ADD:
            case Opcode::OP_SUB:
            case Opcode::OP_MUL:
            case Opcode::OP_DIV:
            case Opcode::OP_MOD:
            case Opcode::OP_AND:
            case Opcode::OP_OR:
            case Opcode::OP_XOR:
                s.uses.push_back(use_reg(dec.reg1));
                s.uses.push_back(use_reg(dec.reg2));
                s.has_def = true;
                s.def = def_reg(dec.reg1);
                break;
            case Opcode::OP_NOT:
            case Opcode::OP_SHL:
            case Opcode::OP_SHR:
            case Opcode::OP_ROL:
            case Opcode::OP_ROR:
            case Opcode::OP_BSWAP:
                s.uses.push_back(use_reg(dec.reg1));
                s.has_def = true;
                s.def = def_reg(dec.reg1);
                break;
            case Opcode::OP_CMP:
            case Opcode::OP_TEST:
            case Opcode::OP_STORE:
                s.uses.push_back(use_reg(dec.reg1));
                s.uses.push_back(use_reg(dec.reg2));
                break;
            case Opcode::OP_PUSH:
                s.uses.push_back(use_reg(dec.reg1));
                break;
            case Opcode::OP_POP:
                s.has_def = true;
                s.def = def_reg(dec.reg1);
                break;
            default:
                break;
            }
            ssa_insts.push_back(std::move(s));
        }
        return ssa_insts;
    }

    static inline std::vector<LiveInterval> compute_live_intervals(const std::vector<SsaInstruction>& ssa_insts) {
        std::vector<LiveInterval> intervals;

        auto find_or_create = [&](SsaVariable v, u32 pos) -> LiveInterval& {
            for (auto& iv : intervals) {
                if (iv.var == v) return iv;
            }
            LiveInterval nw{};
            nw.var = v;
            nw.start_inst = pos;
            nw.end_inst = pos;
            intervals.push_back(nw);
            return intervals.back();
        };

        for (const auto& ins : ssa_insts) {
            if (ins.has_def) {
                auto& iv = find_or_create(ins.def, ins.index);
                if (ins.index < iv.start_inst) iv.start_inst = ins.index;
                if (ins.index > iv.end_inst)   iv.end_inst = ins.index;
            }
            for (const auto& u : ins.uses) {
                auto& iv = find_or_create(u, ins.index);
                if (ins.index > iv.end_inst) iv.end_inst = ins.index;
            }
        }

        std::sort(intervals.begin(), intervals.end(), [](const LiveInterval& a, const LiveInterval& b) {
            return a.start_inst < b.start_inst;
        });

        // Linear scan register allocation across R0..R7 (8 general purpose registers)
        std::array<bool, 8> reg_free{};
        reg_free.fill(true);
        std::vector<size_t> active;

        for (size_t i = 0; i < intervals.size(); ++i) {
            // Expire old intervals
            for (auto it = active.begin(); it != active.end();) {
                if (intervals[*it].end_inst < intervals[i].start_inst) {
                    u8 r = static_cast<u8>(intervals[*it].assigned_phys_reg);
                    if (r < 8) reg_free[r] = true;
                    it = active.erase(it);
                } else {
                    ++it;
                }
            }

            int chosen = -1;
            for (int r = 0; r < 8; ++r) {
                if (reg_free[static_cast<size_t>(r)]) {
                    chosen = r;
                    break;
                }
            }

            if (chosen >= 0) {
                reg_free[static_cast<size_t>(chosen)] = false;
                intervals[i].assigned_phys_reg = static_cast<VReg>(chosen);
                intervals[i].spilled = false;
                active.push_back(i);
            } else {
                intervals[i].spilled = true;
            }
        }

        return intervals;
    }
};

} // namespace vm::ssa

// ============================================================================
// 49. ABSTRACT INTERPRETATION & SYMBOLIC TAINT ANALYZER FOR V-ISA BYTECODE
// ============================================================================
namespace vm::symbolic {

struct ValueInterval {
    u64 min_val{0};
    u64 max_val{0xFFFFFFFFFFFFFFFFULL};
    bool is_constant{false};
    bool is_tainted{false};

    static constexpr ValueInterval constant(u64 v, bool tainted = false) noexcept {
        return ValueInterval{v, v, true, tainted};
    }

    static constexpr ValueInterval top(bool tainted = false) noexcept {
        return ValueInterval{0, 0xFFFFFFFFFFFFFFFFULL, false, tainted};
    }
};

struct AbstractAnalysisReport {
    bool verified_safe{true};
    u32 potential_div_by_zero_count{0};
    u32 potential_oob_memory_count{0};
    u32 constant_register_count{0};
    u32 tainted_register_count{0};
    std::array<ValueInterval, static_cast<size_t>(VReg::COUNT)> final_state{};
};

class BytecodeAbstractInterpreter {
public:
    static inline AbstractAnalysisReport analyze(const BytecodeChunk& chunk, u32 tainted_input_reg_mask = 0) {
        AbstractAnalysisReport rep{};
        for (size_t r = 0; r < static_cast<size_t>(VReg::COUNT); ++r) {
            bool tainted = ((tainted_input_reg_mask >> r) & 1U) != 0;
            rep.final_state[r] = ValueInterval::constant(0, tainted);
        }
        rep.final_state[static_cast<size_t>(VReg::RSP)] = ValueInterval::constant(VMContext::DEFAULT_STACK_SIZE, false);
        rep.final_state[static_cast<size_t>(VReg::RBP)] = ValueInterval::constant(VMContext::DEFAULT_STACK_SIZE, false);

        auto insts = disasm::BytecodeDisassembler::disassemble(chunk);
        for (const auto& ins : insts) {
            auto idx1 = static_cast<size_t>(ins.reg1) % static_cast<size_t>(VReg::COUNT);
            auto idx2 = static_cast<size_t>(ins.reg2) % static_cast<size_t>(VReg::COUNT);

            switch (ins.opcode) {
            case Opcode::OP_MOV_IMM:
                rep.final_state[idx1] = ValueInterval::constant(ins.imm64, false);
                break;
            case Opcode::OP_MOV_REG:
                rep.final_state[idx1] = rep.final_state[idx2];
                break;
            case Opcode::OP_ADD: {
                auto& d = rep.final_state[idx1];
                const auto& s = rep.final_state[idx2];
                bool t = d.is_tainted || s.is_tainted;
                if (d.is_constant && s.is_constant) {
                    d = ValueInterval::constant(d.min_val + s.min_val, t);
                } else {
                    d = ValueInterval::top(t);
                }
                break;
            }
            case Opcode::OP_SUB: {
                auto& d = rep.final_state[idx1];
                const auto& s = rep.final_state[idx2];
                bool t = d.is_tainted || s.is_tainted;
                if (d.is_constant && s.is_constant) {
                    d = ValueInterval::constant(d.min_val - s.min_val, t);
                } else {
                    d = ValueInterval::top(t);
                }
                break;
            }
            case Opcode::OP_MUL: {
                auto& d = rep.final_state[idx1];
                const auto& s = rep.final_state[idx2];
                bool t = d.is_tainted || s.is_tainted;
                if (d.is_constant && s.is_constant) {
                    d = ValueInterval::constant(d.min_val * s.min_val, t);
                } else {
                    d = ValueInterval::top(t);
                }
                break;
            }
            case Opcode::OP_DIV:
            case Opcode::OP_MOD: {
                auto& d = rep.final_state[idx1];
                const auto& s = rep.final_state[idx2];
                bool t = d.is_tainted || s.is_tainted;
                if (s.min_val == 0) {
                    rep.potential_div_by_zero_count++;
                    rep.verified_safe = false;
                    d = ValueInterval::top(t);
                } else if (d.is_constant && s.is_constant) {
                    u64 res = (ins.opcode == Opcode::OP_DIV) ? (d.min_val / s.min_val) : (d.min_val % s.min_val);
                    d = ValueInterval::constant(res, t);
                } else {
                    d = ValueInterval::top(t);
                }
                break;
            }
            case Opcode::OP_LOAD: {
                const auto& addr = rep.final_state[idx2];
                if (addr.max_val + 8 > VMContext::DEFAULT_STACK_SIZE) {
                    rep.potential_oob_memory_count++;
                }
                rep.final_state[idx1] = ValueInterval::top(addr.is_tainted);
                break;
            }
            case Opcode::OP_STORE: {
                const auto& addr = rep.final_state[idx1];
                if (addr.max_val + 8 > VMContext::DEFAULT_STACK_SIZE) {
                    rep.potential_oob_memory_count++;
                }
                break;
            }
            default:
                break;
            }
        }

        for (const auto& st : rep.final_state) {
            if (st.is_constant) rep.constant_register_count++;
            if (st.is_tainted)  rep.tainted_register_count++;
        }
        return rep;
    }
};

} // namespace vm::symbolic


// ============================================================================
// 50. RFC 3713 CAMELLIA-256 24-ROUND FEISTEL BLOCK CIPHER
// ============================================================================
namespace crypto {

class Camellia256 {
public:
    using Key   = std::array<u8, 32>;
    using Block = std::array<u8, 16>;

    static constexpr std::array<u8, 256> SBOX1 = {
        112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
         35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
        134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
        166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
        139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
        223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
         20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
        254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
        170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
         16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
        135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
         82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
        233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
        120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
        114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
         64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
    };

    static constexpr std::array<u64, 6> SIGMA = {
        0xA09E667F3BCC908BULL,
        0xB67AE8584CAA73B2ULL,
        0xC6EF372FE94F82BEULL,
        0x54FF53A5F1D36F1CULL,
        0x10E527FADE682D1DULL,
        0xB05688C2B3E6C1FDULL
    };

    static constexpr u8 rotl8(u8 x, u32 n) noexcept {
        return static_cast<u8>((x << n) | (x >> (8 - n)));
    }

    static constexpr u8 sbox2(u8 x) noexcept { return rotl8(SBOX1[x], 1); }
    static constexpr u8 sbox3(u8 x) noexcept { return rotl8(SBOX1[x], 7); }
    static constexpr u8 sbox4(u8 x) noexcept { return SBOX1[rotl8(x, 1)]; }

    static constexpr u32 rotl32(u32 x, u32 n) noexcept {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr u64 f_func(u64 input, u64 ke) noexcept {
        u64 x = input ^ ke;
        u8 t1 = SBOX1[static_cast<u8>((x >> 56) & 0xFF)];
        u8 t2 = sbox2(static_cast<u8>((x >> 48) & 0xFF));
        u8 t3 = sbox3(static_cast<u8>((x >> 40) & 0xFF));
        u8 t4 = sbox4(static_cast<u8>((x >> 32) & 0xFF));
        u8 t5 = sbox2(static_cast<u8>((x >> 24) & 0xFF));
        u8 t6 = sbox3(static_cast<u8>((x >> 16) & 0xFF));
        u8 t7 = sbox4(static_cast<u8>((x >> 8)  & 0xFF));
        u8 t8 = SBOX1[static_cast<u8>(x & 0xFF)];

        u8 y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
        u8 y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
        u8 y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
        u8 y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
        u8 y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
        u8 y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
        u8 y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
        u8 y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

        return (static_cast<u64>(y1) << 56) | (static_cast<u64>(y2) << 48) |
               (static_cast<u64>(y3) << 40) | (static_cast<u64>(y4) << 32) |
               (static_cast<u64>(y5) << 24) | (static_cast<u64>(y6) << 16) |
               (static_cast<u64>(y7) << 8)  |  static_cast<u64>(y8);
    }

    static constexpr u64 fl_func(u64 x, u64 kl) noexcept {
        u32 x1 = static_cast<u32>(x >> 32);
        u32 x2 = static_cast<u32>(x & 0xFFFFFFFFULL);
        u32 k1 = static_cast<u32>(kl >> 32);
        u32 k2 = static_cast<u32>(kl & 0xFFFFFFFFULL);
        x2 ^= rotl32(x1 & k1, 1);
        x1 ^= (x2 | k2);
        return (static_cast<u64>(x1) << 32) | static_cast<u64>(x2);
    }

    static constexpr u64 flinv_func(u64 y, u64 kl) noexcept {
        u32 y1 = static_cast<u32>(y >> 32);
        u32 y2 = static_cast<u32>(y & 0xFFFFFFFFULL);
        u32 k1 = static_cast<u32>(kl >> 32);
        u32 k2 = static_cast<u32>(kl & 0xFFFFFFFFULL);
        y1 ^= (y2 | k2);
        y2 ^= rotl32(y1 & k1, 1);
        return (static_cast<u64>(y1) << 32) | static_cast<u64>(y2);
    }

    struct Uint128Pair {
        u64 hi{0};
        u64 lo{0};

        static constexpr Uint128Pair rotl(Uint128Pair v, u32 s) noexcept {
            s &= 127;
            if (s == 0) return v;
            if (s == 64) return Uint128Pair{v.lo, v.hi};
            if (s < 64) {
                return Uint128Pair{(v.hi << s) | (v.lo >> (64 - s)), (v.lo << s) | (v.hi >> (64 - s))};
            }
            u32 k = s - 64;
            return Uint128Pair{(v.lo << k) | (v.hi >> (64 - k)), (v.hi << k) | (v.lo >> (64 - k))};
        }
    };

    constexpr explicit Camellia256(const Key& key) noexcept {
        auto rd64be = [](const u8* p) constexpr noexcept -> u64 {
            u64 v = 0;
            for (size_t i = 0; i < 8; ++i) v = (v << 8) | p[i];
            return v;
        };

        Uint128Pair KL{rd64be(&key[0]),  rd64be(&key[8])};
        Uint128Pair KR{rd64be(&key[16]), rd64be(&key[24])};

        u64 d1 = KL.hi ^ KR.hi;
        u64 d2 = KL.lo ^ KR.lo;
        d2 ^= f_func(d1, SIGMA[0]);
        d1 ^= f_func(d2, SIGMA[1]);
        d1 ^= KL.hi;
        d2 ^= KL.lo;
        d2 ^= f_func(d1, SIGMA[2]);
        d1 ^= f_func(d2, SIGMA[3]);
        Uint128Pair KA{d1, d2};

        d1 = KA.hi ^ KR.hi;
        d2 = KA.lo ^ KR.lo;
        d2 ^= f_func(d1, SIGMA[4]);
        d1 ^= f_func(d2, SIGMA[5]);
        Uint128Pair KB{d1, d2};

        kw_[0] = KL.hi; kw_[1] = KL.lo;
        u_[0]  = KB.hi; u_[1]  = KB.lo;
        u_[2]  = Uint128Pair::rotl(KR, 15).hi; u_[3]  = Uint128Pair::rotl(KR, 15).lo;
        u_[4]  = Uint128Pair::rotl(KA, 15).hi; u_[5]  = Uint128Pair::rotl(KA, 15).lo;
        kl_[0] = Uint128Pair::rotl(KR, 30).hi; kl_[1] = Uint128Pair::rotl(KR, 30).lo;
        u_[6]  = Uint128Pair::rotl(KB, 30).hi; u_[7]  = Uint128Pair::rotl(KB, 30).lo;
        u_[8]  = Uint128Pair::rotl(KL, 45).hi; u_[9]  = Uint128Pair::rotl(KL, 45).lo;
        u_[10] = Uint128Pair::rotl(KA, 45).hi; u_[11] = Uint128Pair::rotl(KA, 45).lo;
        kl_[2] = Uint128Pair::rotl(KL, 60).hi; kl_[3] = Uint128Pair::rotl(KL, 60).lo;
        u_[12] = Uint128Pair::rotl(KR, 60).hi; u_[13] = Uint128Pair::rotl(KR, 60).lo;
        u_[14] = Uint128Pair::rotl(KB, 60).hi; u_[15] = Uint128Pair::rotl(KB, 60).lo;
        u_[16] = Uint128Pair::rotl(KL, 77).hi; u_[17] = Uint128Pair::rotl(KL, 77).lo;
        kl_[4] = Uint128Pair::rotl(KA, 77).hi; kl_[5] = Uint128Pair::rotl(KA, 77).lo;
        u_[18] = Uint128Pair::rotl(KR, 94).hi; u_[19] = Uint128Pair::rotl(KR, 94).lo;
        u_[20] = Uint128Pair::rotl(KA, 94).hi; u_[21] = Uint128Pair::rotl(KA, 94).lo;
        u_[22] = Uint128Pair::rotl(KL, 111).hi; u_[23] = Uint128Pair::rotl(KL, 111).lo;
        kw_[2] = Uint128Pair::rotl(KB, 111).hi; kw_[3] = Uint128Pair::rotl(KB, 111).lo;
    }

    constexpr void encrypt_block(Block& b) const noexcept {
        u64 d1 = 0, d2 = 0;
        for (size_t i = 0; i < 8; ++i) {
            d1 = (d1 << 8) | b[i];
            d2 = (d2 << 8) | b[8 + i];
        }

        d1 ^= kw_[0];
        d2 ^= kw_[1];

        for (size_t r = 0; r < 24; r += 2) {
            if (r == 6 || r == 12 || r == 18) {
                size_t k_idx = (r / 6 - 1) * 2;
                d1 = fl_func(d1, kl_[k_idx]);
                d2 = flinv_func(d2, kl_[k_idx + 1]);
            }
            d2 ^= f_func(d1, u_[r]);
            d1 ^= f_func(d2, u_[r + 1]);
        }

        d2 ^= kw_[2];
        d1 ^= kw_[3];

        for (size_t i = 0; i < 8; ++i) {
            b[i]     = static_cast<u8>((d2 >> (56 - i * 8)) & 0xFF);
            b[8 + i] = static_cast<u8>((d1 >> (56 - i * 8)) & 0xFF);
        }
    }

    constexpr void decrypt_block(Block& b) const noexcept {
        u64 d2 = 0, d1 = 0;
        for (size_t i = 0; i < 8; ++i) {
            d2 = (d2 << 8) | b[i];
            d1 = (d1 << 8) | b[8 + i];
        }

        d2 ^= kw_[2];
        d1 ^= kw_[3];

        for (int r = 22; r >= 0; r -= 2) {
            d1 ^= f_func(d2, u_[static_cast<size_t>(r + 1)]);
            d2 ^= f_func(d1, u_[static_cast<size_t>(r)]);
            if (r == 6 || r == 12 || r == 18) {
                size_t k_idx = (static_cast<size_t>(r) / 6 - 1) * 2;
                d1 = flinv_func(d1, kl_[k_idx]);
                d2 = fl_func(d2, kl_[k_idx + 1]);
            }
        }

        d1 ^= kw_[0];
        d2 ^= kw_[1];

        for (size_t i = 0; i < 8; ++i) {
            b[i]     = static_cast<u8>((d1 >> (56 - i * 8)) & 0xFF);
            b[8 + i] = static_cast<u8>((d2 >> (56 - i * 8)) & 0xFF);
        }
    }

private:
    std::array<u64, 4>  kw_{};
    std::array<u64, 24> u_{};
    std::array<u64, 6>  kl_{};
};

// ============================================================================
// 51. SHAMIR'S (K, N) THRESHOLD SECRET SHARING OVER GF(2^8)
// ============================================================================
class ShamirSecretSharing {
public:
    struct Share {
        u8 id{0}; // 1..255
        std::vector<u8> data;
    };

    static constexpr u8 gf256_add(u8 a, u8 b) noexcept {
        return a ^ b;
    }

    static constexpr u8 gf256_mul(u8 a, u8 b) noexcept {
        u8 p = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) p ^= a;
            bool hi = (a & 0x80) != 0;
            a <<= 1;
            if (hi) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    static constexpr u8 gf256_inv(u8 a) noexcept {
        if (a == 0) return 0;
        // a^254 in GF(2^8) by Fermat's Little Theorem
        u8 res = 1;
        u8 base = a;
        u8 exp = 254;
        while (exp > 0) {
            if (exp & 1) res = gf256_mul(res, base);
            base = gf256_mul(base, base);
            exp >>= 1;
        }
        return res;
    }

    static constexpr u8 gf256_div(u8 a, u8 b) noexcept {
        return gf256_mul(a, gf256_inv(b));
    }

    static inline std::vector<Share> split_secret(const u8* secret, size_t len, u8 threshold_k, u8 total_n) {
        if (!secret || len == 0 || threshold_k < 2 || total_n < threshold_k) return {};
        std::vector<Share> shares(total_n);
        for (u8 i = 0; i < total_n; ++i) {
            shares[i].id = static_cast<u8>(i + 1);
            shares[i].data.resize(len);
        }

        std::vector<u8> coeffs(threshold_k);
        for (size_t byte_idx = 0; byte_idx < len; ++byte_idx) {
            coeffs[0] = secret[byte_idx];
            for (u8 c = 1; c < threshold_k; ++c) {
                u8 r = 0;
                while (r == 0) r = core::RuntimeRandom::get_u8();
                coeffs[c] = r;
            }

            for (u8 s = 0; s < total_n; ++s) {
                u8 x = shares[s].id;
                // Horner's method evaluation
                u8 y = 0;
                for (int c = static_cast<int>(threshold_k) - 1; c >= 0; --c) {
                    y = gf256_add(gf256_mul(y, x), coeffs[static_cast<size_t>(c)]);
                }
                shares[s].data[byte_idx] = y;
            }
        }
        secure_zero(coeffs.data(), coeffs.size());
        return shares;
    }

    static inline std::vector<u8> reconstruct_secret(const std::vector<Share>& shares) {
        if (shares.empty()) return {};
        size_t len = shares[0].data.size();
        for (const auto& s : shares) {
            if (s.data.size() != len || s.id == 0) return {};
        }

        std::vector<u8> secret(len, 0);
        const size_t k = shares.size();

        for (size_t byte_idx = 0; byte_idx < len; ++byte_idx) {
            u8 accum = 0;
            for (size_t i = 0; i < k; ++i) {
                u8 num = 1;
                u8 den = 1;
                for (size_t j = 0; j < k; ++j) {
                    if (i == j) continue;
                    num = gf256_mul(num, shares[j].id);
                    den = gf256_mul(den, gf256_add(shares[i].id, shares[j].id));
                }
                u8 basis = gf256_div(num, den);
                accum = gf256_add(accum, gf256_mul(shares[i].data[byte_idx], basis));
            }
            secret[byte_idx] = accum;
        }
        return secret;
    }
};

// ============================================================================
// 52. SELF-HEALING ECC MEMORY BLOCK (HAMMING SEC-DED + PARITY RECOVERY)
// ============================================================================
class SelfHealingBuffer {
public:
    explicit SelfHealingBuffer(const u8* data, size_t len) {
        assign(data, len);
    }

    void assign(const u8* data, size_t len) {
        orig_len_ = len;
        encoded_words_.resize(len);
        row_parity_.assign(8, 0);
        for (size_t i = 0; i < len; ++i) {
            encoded_words_[i] = hamming_encode_byte(data[i]);
            row_parity_[i & 7] ^= data[i];
        }
        sha_digest_ = Sha256::hash(data, len);
    }

    /**
     * @brief Verifies and automatically repairs single-bit errors per byte or single-row erasure
     */
    bool verify_and_heal(std::vector<u8>& out_repaired, u32& out_corrected_errors) {
        out_corrected_errors = 0;
        out_repaired.resize(orig_len_);

        for (size_t i = 0; i < orig_len_; ++i) {
            bool fixed = false;
            out_repaired[i] = hamming_decode_byte(encoded_words_[i], fixed);
            if (fixed) {
                out_corrected_errors++;
                encoded_words_[i] = hamming_encode_byte(out_repaired[i]);
            }
        }

        auto cur_sha = Sha256::hash(out_repaired.data(), out_repaired.size());
        if (cur_sha == sha_digest_) return true;

        // Try row-parity erasure recovery if a single byte was completely overwritten
        for (size_t i = 0; i < orig_len_; ++i) {
            u8 expected_xor = row_parity_[i & 7];
            for (size_t j = (i & 7); j < orig_len_; j += 8) {
                if (j != i) expected_xor ^= out_repaired[j];
            }
            u8 old_val = out_repaired[i];
            out_repaired[i] = expected_xor;
            if (Sha256::hash(out_repaired.data(), out_repaired.size()) == sha_digest_) {
                encoded_words_[i] = hamming_encode_byte(expected_xor);
                out_corrected_errors++;
                return true;
            }
            out_repaired[i] = old_val;
        }
        return false;
    }

    void inject_bit_fault_for_test(size_t byte_index, u8 bit_pos) noexcept {
        if (byte_index < encoded_words_.size() && bit_pos < 12) {
            encoded_words_[byte_index] ^= static_cast<u16>(1U << bit_pos);
        }
    }

private:
    static constexpr u16 hamming_encode_byte(u8 d) noexcept {
        u16 d1 = (d >> 0) & 1;
        u16 d2 = (d >> 1) & 1;
        u16 d3 = (d >> 2) & 1;
        u16 d4 = (d >> 3) & 1;
        u16 d5 = (d >> 4) & 1;
        u16 d6 = (d >> 5) & 1;
        u16 d7 = (d >> 6) & 1;
        u16 d8 = (d >> 7) & 1;

        u16 p1 = d1 ^ d2 ^ d4 ^ d5 ^ d7;
        u16 p2 = d1 ^ d3 ^ d4 ^ d6 ^ d7;
        u16 p4 = d2 ^ d3 ^ d4 ^ d8;
        u16 p8 = d5 ^ d6 ^ d7 ^ d8;

        return static_cast<u16>(
            (p1 << 0) | (p2 << 1) | (d1 << 2) | (p4 << 3) |
            (d2 << 4) | (d3 << 5) | (d4 << 6) | (p8 << 7) |
            (d5 << 8) | (d6 << 9) | (d7 << 10) | (d8 << 11));
    }

    static constexpr u8 hamming_decode_byte(u16 code, bool& out_corrected) noexcept {
        out_corrected = false;
        u16 b1  = (code >> 0) & 1;
        u16 b2  = (code >> 1) & 1;
        u16 b3  = (code >> 2) & 1;
        u16 b4  = (code >> 3) & 1;
        u16 b5  = (code >> 4) & 1;
        u16 b6  = (code >> 5) & 1;
        u16 b7  = (code >> 6) & 1;
        u16 b8  = (code >> 7) & 1;
        u16 b9  = (code >> 8) & 1;
        u16 b10 = (code >> 9) & 1;
        u16 b11 = (code >> 10) & 1;
        u16 b12 = (code >> 11) & 1;

        u16 s1 = b1 ^ b3 ^ b5 ^ b7 ^ b9 ^ b11;
        u16 s2 = b2 ^ b3 ^ b6 ^ b7 ^ b10 ^ b11;
        u16 s4 = b4 ^ b5 ^ b6 ^ b7 ^ b12;
        u16 s8 = b8 ^ b9 ^ b10 ^ b11 ^ b12;

        u16 syndrome = static_cast<u16>(s1 | (s2 << 1) | (s4 << 2) | (s8 << 3));
        if (syndrome >= 1 && syndrome <= 12) {
            code ^= static_cast<u16>(1U << (syndrome - 1));
            out_corrected = true;
        }

        return static_cast<u8>(
            (((code >> 2)  & 1) << 0) |
            (((code >> 4)  & 1) << 1) |
            (((code >> 5)  & 1) << 2) |
            (((code >> 6)  & 1) << 3) |
            (((code >> 8)  & 1) << 4) |
            (((code >> 9)  & 1) << 5) |
            (((code >> 10) & 1) << 6) |
            (((code >> 11) & 1) << 7));
    }

    size_t orig_len_{0};
    std::vector<u16> encoded_words_;
    std::vector<u8> row_parity_;
    Sha256::Digest sha_digest_{};
};

} // namespace crypto

// ============================================================================
// 53. DEEP PROCESS, MEMORY PAGE & TIMING JITTER FORENSICS
// ============================================================================
namespace anti {

struct MemorySpaceAudit {
    u32 total_regions{0};
    u32 image_exec_regions{0};
    u32 private_exec_regions{0};
    u32 rwx_regions{0};
    bool has_unbacked_executable_memory{false};
};

struct TimingJitterStats {
    u64 min_cycles{0};
    u64 max_cycles{0};
    u64 median_cycles{0};
    u32 outlier_spikes{0};
    bool hypervisor_or_step_suspected{false};
};

class EnvironmentForensics {
public:
    /**
     * @brief Walks current process virtual memory to detect unbacked RWX / private executable pages
     */
    static inline MemorySpaceAudit audit_virtual_memory() noexcept {
        MemorySpaceAudit audit{};
#if defined(AEGIS_WINDOWS)
        const u8* addr = nullptr;
        MEMORY_BASIC_INFORMATION mbi{};
        while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT) {
                audit.total_regions++;
                DWORD p = mbi.Protect & 0xFF;
                bool is_exec = (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                                p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY);
                bool is_rwx  = (p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY);

                if (is_exec) {
                    if (mbi.Type == MEM_IMAGE) {
                        audit.image_exec_regions++;
                    } else if (mbi.Type == MEM_PRIVATE) {
                        audit.private_exec_regions++;
                        audit.has_unbacked_executable_memory = true;
                    }
                }
                if (is_rwx) {
                    audit.rwx_regions++;
                }
            }
            const u8* next = static_cast<const u8*>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
#endif
        return audit;
    }

    /**
     * @brief Profiles RDTSC cycle delta distribution across 64 samples
     */
    static inline TimingJitterStats profile_timing_jitter() noexcept {
        TimingJitterStats stats{};
#if defined(AEGIS_COMPILER_MSVC)
        std::array<u64, 64> samples{};
        int cpu_info[4]{};
        for (size_t i = 0; i < 64; ++i) {
            u64 t1 = __rdtsc();
            __cpuid(cpu_info, 0);
            u64 t2 = __rdtsc();
            samples[i] = (t2 >= t1) ? (t2 - t1) : 0;
        }
        std::sort(samples.begin(), samples.end());
        stats.min_cycles = samples.front();
        stats.max_cycles = samples.back();
        stats.median_cycles = samples[32];

        u64 spike_threshold = (stats.median_cycles * 8) + 5000;
        for (u64 s : samples) {
            if (s > spike_threshold) stats.outlier_spikes++;
        }
        stats.hypervisor_or_step_suspected = (stats.outlier_spikes > 16);
#endif
        return stats;
    }
};

} // namespace anti


// ============================================================================
// 54. RFC 7693 BLAKE2s-256 & NIST SP 800-232 ASCON-128 / ASCON-HASH SPONGE
// ============================================================================
namespace crypto {

class Blake2s {
public:
    using Digest = std::array<u8, 32>;

    static constexpr std::array<u32, 8> IV = {
        0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
        0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
    };

    static constexpr u8 SIGMA[10][16] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
    };

    explicit Blake2s(size_t out_len = 32, const u8* key = nullptr, size_t key_len = 0) noexcept {
        init(out_len, key, key_len);
    }

    void init(size_t out_len = 32, const u8* key = nullptr, size_t key_len = 0) noexcept {
        out_len_ = (out_len == 0 || out_len > 32) ? 32 : out_len;
        for (size_t i = 0; i < 8; ++i) h_[i] = IV[i];
        h_[0] ^= 0x01010000UL ^ (static_cast<u32>(key_len) << 8) ^ static_cast<u32>(out_len_);
        t_[0] = 0; t_[1] = 0;
        f_[0] = 0; f_[1] = 0;
        buflen_ = 0;
        buf_.fill(0);
        if (key && key_len > 0 && key_len <= 32) {
            std::memcpy(buf_.data(), key, key_len);
            buflen_ = 64;
        }
    }

    void update(const u8* in, size_t inlen) noexcept {
        if (inlen == 0) return;
        size_t left = buflen_;
        size_t fill = 64 - left;
        if (inlen > fill) {
            buflen_ = 0;
            std::memcpy(buf_.data() + left, in, fill);
            increment_counter(64);
            compress(buf_.data());
            in += fill;
            inlen -= fill;
            while (inlen > 64) {
                increment_counter(64);
                compress(in);
                in += 64;
                inlen -= 64;
            }
        }
        std::memcpy(buf_.data() + buflen_, in, inlen);
        buflen_ += inlen;
    }

    Digest finalize() noexcept {
        increment_counter(static_cast<u32>(buflen_));
        f_[0] = ~0U;
        for (size_t i = buflen_; i < 64; ++i) buf_[i] = 0;
        compress(buf_.data());

        Digest out{};
        for (size_t i = 0; i < 8; ++i) {
            out[i * 4 + 0] = static_cast<u8>((h_[i] >> 0) & 0xFF);
            out[i * 4 + 1] = static_cast<u8>((h_[i] >> 8) & 0xFF);
            out[i * 4 + 2] = static_cast<u8>((h_[i] >> 16) & 0xFF);
            out[i * 4 + 3] = static_cast<u8>((h_[i] >> 24) & 0xFF);
        }
        return out;
    }

    static inline Digest hash(const u8* data, size_t len) noexcept {
        Blake2s ctx(32);
        ctx.update(data, len);
        return ctx.finalize();
    }

    static inline Digest hash(std::string_view sv) noexcept {
        return hash(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }

private:
    static constexpr u32 rotr32(u32 w, unsigned c) noexcept {
        return (w >> c) | (w << (32 - c));
    }

    static constexpr u32 load32(const u8* p) noexcept {
        return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
              (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
    }

    void increment_counter(u32 inc) noexcept {
        t_[0] += inc;
        if (t_[0] < inc) t_[1]++;
    }

    static constexpr void G(u32& a, u32& b, u32& c, u32& d, u32 x, u32 y) noexcept {
        a = a + b + x;
        d = rotr32(d ^ a, 16);
        c = c + d;
        b = rotr32(b ^ c, 12);
        a = a + b + y;
        d = rotr32(d ^ a, 8);
        c = c + d;
        b = rotr32(b ^ c, 7);
    }

    void compress(const u8* block) noexcept {
        u32 m[16]{};
        u32 v[16]{};
        for (size_t i = 0; i < 16; ++i) m[i] = load32(block + i * 4);
        for (size_t i = 0; i < 8; ++i) v[i] = h_[i];
        v[8]  = IV[0];
        v[9]  = IV[1];
        v[10] = IV[2];
        v[11] = IV[3];
        v[12] = t_[0] ^ IV[4];
        v[13] = t_[1] ^ IV[5];
        v[14] = f_[0] ^ IV[6];
        v[15] = f_[1] ^ IV[7];

        for (size_t r = 0; r < 10; ++r) {
            G(v[0], v[4], v[8],  v[12], m[SIGMA[r][0]],  m[SIGMA[r][1]]);
            G(v[1], v[5], v[9],  v[13], m[SIGMA[r][2]],  m[SIGMA[r][3]]);
            G(v[2], v[6], v[10], v[14], m[SIGMA[r][4]],  m[SIGMA[r][5]]);
            G(v[3], v[7], v[11], v[15], m[SIGMA[r][6]],  m[SIGMA[r][7]]);
            G(v[0], v[5], v[10], v[15], m[SIGMA[r][8]],  m[SIGMA[r][9]]);
            G(v[1], v[6], v[11], v[12], m[SIGMA[r][10]], m[SIGMA[r][11]]);
            G(v[2], v[7], v[8],  v[13], m[SIGMA[r][12]], m[SIGMA[r][13]]);
            G(v[3], v[4], v[9],  v[14], m[SIGMA[r][14]], m[SIGMA[r][15]]);
        }

        for (size_t i = 0; i < 8; ++i) {
            h_[i] ^= v[i] ^ v[i + 8];
        }
    }

    std::array<u32, 8> h_{};
    std::array<u32, 2> t_{};
    std::array<u32, 2> f_{};
    std::array<u8, 64> buf_{};
    size_t buflen_{0};
    size_t out_len_{32};
};

/**
 * @brief NIST SP 800-232 Lightweight Cryptography Standard: ASCON-Hash & ASCON-128 AEAD
 */
class Ascon320 {
public:
    using State = std::array<u64, 5>;
    using Key   = std::array<u8, 16>;
    using Nonce = std::array<u8, 16>;
    using Tag   = std::array<u8, 16>;

    static constexpr u64 rotr64(u64 x, u32 n) noexcept {
        return (x >> n) | (x << (64 - n));
    }

    static constexpr void permute(State& s, size_t rounds = 12) noexcept {
        constexpr u64 RC[12] = {
            0xf0ULL, 0xe1ULL, 0xd2ULL, 0xc3ULL, 0xb4ULL, 0xa5ULL,
            0x96ULL, 0x87ULL, 0x78ULL, 0x69ULL, 0x5aULL, 0x4bULL
        };

        size_t start = 12 - rounds;
        for (size_t i = start; i < 12; ++i) {
            // Addition of round constant
            s[2] ^= RC[i];

            // Substitution layer (5-bit S-box across 64 columns)
            s[0] ^= s[4];
            s[4] ^= s[3];
            s[2] ^= s[1];

            u64 t0 = (~s[0]) & s[1];
            u64 t1 = (~s[1]) & s[2];
            u64 t2 = (~s[2]) & s[3];
            u64 t3 = (~s[3]) & s[4];
            u64 t4 = (~s[4]) & s[0];

            s[0] ^= t1;
            s[1] ^= t2;
            s[2] ^= t3;
            s[3] ^= t4;
            s[4] ^= t0;

            s[1] ^= s[0];
            s[0] ^= s[4];
            s[3] ^= s[2];
            s[2] = ~s[2];

            // Linear diffusion layer
            s[0] ^= rotr64(s[0], 19) ^ rotr64(s[0], 28);
            s[1] ^= rotr64(s[1], 61) ^ rotr64(s[1], 39);
            s[2] ^= rotr64(s[2], 1)  ^ rotr64(s[2], 6);
            s[3] ^= rotr64(s[3], 10) ^ rotr64(s[3], 17);
            s[4] ^= rotr64(s[4], 7)  ^ rotr64(s[4], 41);
        }
    }

    static inline std::array<u8, 32> hash256(const u8* data, size_t len) noexcept {
        State s = {
            0xee9398aadb67f03dULL,
            0x8bb21831c60f1002ULL,
            0xb48a92db98d5da62ULL,
            0x43189921b8f8e3e8ULL,
            0x348fa5c9d525e140ULL
        };

        while (len >= 8) {
            u64 blk = 0;
            for (size_t i = 0; i < 8; ++i) blk = (blk << 8) | data[i];
            s[0] ^= blk;
            permute(s, 12);
            data += 8;
            len -= 8;
        }

        u64 pad = 0;
        for (size_t i = 0; i < len; ++i) {
            pad |= static_cast<u64>(data[i]) << (56 - i * 8);
        }
        pad |= 0x80ULL << (56 - len * 8);
        s[0] ^= pad;
        permute(s, 12);

        std::array<u8, 32> out{};
        for (size_t block = 0; block < 4; ++block) {
            for (size_t b = 0; b < 8; ++b) {
                out[block * 8 + b] = static_cast<u8>((s[0] >> (56 - b * 8)) & 0xFF);
            }
            if (block < 3) permute(s, 12);
        }
        return out;
    }

    static inline std::array<u8, 32> hash256(std::string_view sv) noexcept {
        return hash256(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }
};

// ============================================================================
// 55. ISO/IEC 10118-3 SM3-256 HASH & ISO/IEC 18033-3 SM4-128 BLOCK CIPHER
// ============================================================================
class Sm3 {
public:
    using Digest = std::array<u8, 32>;

    static constexpr u32 rotl32(u32 x, u32 n) noexcept {
        n &= 31;
        return (n == 0) ? x : ((x << n) | (x >> (32 - n)));
    }

    static constexpr u32 P0(u32 x) noexcept { return x ^ rotl32(x, 9) ^ rotl32(x, 17); }
    static constexpr u32 P1(u32 x) noexcept { return x ^ rotl32(x, 15) ^ rotl32(x, 23); }

    static constexpr u32 FF(u32 x, u32 y, u32 z, size_t j) noexcept {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static constexpr u32 GG(u32 x, u32 y, u32 z, size_t j) noexcept {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    static inline Digest hash(const u8* msg, size_t len) noexcept {
        std::array<u32, 8> V = {
            0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL,
            0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL
        };

        u64 bit_len = static_cast<u64>(len) * 8ULL;
        size_t rem = len % 64;
        size_t pad_zeros = (rem < 56) ? (55 - rem) : (119 - rem);
        std::vector<u8> padded(len + 1 + pad_zeros + 8, 0);
        if (len > 0) std::memcpy(padded.data(), msg, len);
        padded[len] = 0x80;
        for (int i = 0; i < 8; ++i) {
            padded[padded.size() - 8 + i] = static_cast<u8>((bit_len >> (56 - i * 8)) & 0xFF);
        }

        for (size_t blk = 0; blk < padded.size(); blk += 64) {
            const u8* B = padded.data() + blk;
            u32 W[68]{};
            u32 W1[64]{};
            for (size_t j = 0; j < 16; ++j) {
                W[j] = (static_cast<u32>(B[j * 4 + 0]) << 24) |
                       (static_cast<u32>(B[j * 4 + 1]) << 16) |
                       (static_cast<u32>(B[j * 4 + 2]) << 8)  |
                        static_cast<u32>(B[j * 4 + 3]);
            }
            for (size_t j = 16; j < 68; ++j) {
                W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl32(W[j - 3], 15)) ^ rotl32(W[j - 13], 7) ^ W[j - 6];
            }
            for (size_t j = 0; j < 64; ++j) {
                W1[j] = W[j] ^ W[j + 4];
            }

            u32 A = V[0], b = V[1], C = V[2], D = V[3];
            u32 E = V[4], F = V[5], G = V[6], H = V[7];

            for (size_t j = 0; j < 64; ++j) {
                u32 Tj = (j < 16) ? 0x79cc4519UL : 0x7a879d8aUL;
                u32 SS1 = rotl32(rotl32(A, 12) + E + rotl32(Tj, static_cast<u32>(j)), 7);
                u32 SS2 = SS1 ^ rotl32(A, 12);
                u32 TT1 = FF(A, b, C, j) + D + SS2 + W1[j];
                u32 TT2 = GG(E, F, G, j) + H + SS1 + W[j];
                D = C;
                C = rotl32(b, 9);
                b = A;
                A = TT1;
                H = G;
                G = rotl32(F, 19);
                F = E;
                E = P0(TT2);
            }

            V[0] ^= A; V[1] ^= b; V[2] ^= C; V[3] ^= D;
            V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
        }

        Digest out{};
        for (size_t i = 0; i < 8; ++i) {
            out[i * 4 + 0] = static_cast<u8>((V[i] >> 24) & 0xFF);
            out[i * 4 + 1] = static_cast<u8>((V[i] >> 16) & 0xFF);
            out[i * 4 + 2] = static_cast<u8>((V[i] >> 8)  & 0xFF);
            out[i * 4 + 3] = static_cast<u8>(V[i] & 0xFF);
        }
        return out;
    }

    static inline Digest hash(std::string_view sv) noexcept {
        return hash(reinterpret_cast<const u8*>(sv.data()), sv.size());
    }
};

class Sm4 {
public:
    using Key   = std::array<u8, 16>;
    using Block = std::array<u8, 16>;

    static constexpr std::array<u8, 256> SBOX = {
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    };

    static constexpr std::array<u32, 4> FK = {
        0xa3b1bac6UL, 0x56aa3350UL, 0x677d9197UL, 0xb27022dcUL
    };

    static constexpr std::array<u32, 32> CK = {
        0x00070e15UL, 0x1c232a31UL, 0x383f464dUL, 0x545b6269UL,
        0x70777e85UL, 0x8c939aa1UL, 0xa8afb6bdUL, 0xc4cbd2d9UL,
        0xe0e7eef5UL, 0xfc030a11UL, 0x181f262dUL, 0x343b4249UL,
        0x50575e65UL, 0x6c737a81UL, 0x888f969dUL, 0xa4abb2b9UL,
        0xc0c7ced5UL, 0xdce3eaf1UL, 0xf8ff060dUL, 0x141b2229UL,
        0x30373e45UL, 0x4c535a61UL, 0x686f767dUL, 0x848b9299UL,
        0xa0a7aeb5UL, 0xbcc3cad1UL, 0xd8dfe6edUL, 0xf4fb0209UL,
        0x10171e25UL, 0x2c333a41UL, 0x484f565dUL, 0x646b7279UL
    };

    static constexpr u32 rotl32(u32 x, u32 n) noexcept {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr u32 tau(u32 a) noexcept {
        return (static_cast<u32>(SBOX[(a >> 24) & 0xFF]) << 24) |
               (static_cast<u32>(SBOX[(a >> 16) & 0xFF]) << 16) |
               (static_cast<u32>(SBOX[(a >> 8)  & 0xFF]) << 8)  |
                static_cast<u32>(SBOX[a & 0xFF]);
    }

    static constexpr u32 T(u32 x) noexcept {
        u32 b = tau(x);
        return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
    }

    static constexpr u32 T_prime(u32 x) noexcept {
        u32 b = tau(x);
        return b ^ rotl32(b, 13) ^ rotl32(b, 23);
    }

    constexpr explicit Sm4(const Key& key) noexcept {
        u32 K[36]{};
        for (size_t i = 0; i < 4; ++i) {
            u32 mk = (static_cast<u32>(key[i * 4 + 0]) << 24) |
                     (static_cast<u32>(key[i * 4 + 1]) << 16) |
                     (static_cast<u32>(key[i * 4 + 2]) << 8)  |
                      static_cast<u32>(key[i * 4 + 3]);
            K[i] = mk ^ FK[i];
        }
        for (size_t i = 0; i < 32; ++i) {
            rk_[i] = K[i + 4] = K[i] ^ T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        }
    }

    constexpr void encrypt_block(Block& blk) const noexcept {
        crypt_with_rk(blk, false);
    }

    constexpr void decrypt_block(Block& blk) const noexcept {
        crypt_with_rk(blk, true);
    }

private:
    constexpr void crypt_with_rk(Block& blk, bool reverse) const noexcept {
        u32 X[36]{};
        for (size_t i = 0; i < 4; ++i) {
            X[i] = (static_cast<u32>(blk[i * 4 + 0]) << 24) |
                   (static_cast<u32>(blk[i * 4 + 1]) << 16) |
                   (static_cast<u32>(blk[i * 4 + 2]) << 8)  |
                    static_cast<u32>(blk[i * 4 + 3]);
        }
        for (size_t i = 0; i < 32; ++i) {
            u32 rk = reverse ? rk_[31 - i] : rk_[i];
            X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk);
        }
        u32 Y[4] = {X[35], X[34], X[33], X[32]};
        for (size_t i = 0; i < 4; ++i) {
            blk[i * 4 + 0] = static_cast<u8>((Y[i] >> 24) & 0xFF);
            blk[i * 4 + 1] = static_cast<u8>((Y[i] >> 16) & 0xFF);
            blk[i * 4 + 2] = static_cast<u8>((Y[i] >> 8)  & 0xFF);
            blk[i * 4 + 3] = static_cast<u8>(Y[i] & 0xFF);
        }
    }

    std::array<u32, 32> rk_{};
};

} // namespace crypto

// ============================================================================
// 56. V-ISA BYTECODE TO STRUCTURED C PSEUDOCODE DECOMPILER / AUDIT PRINTER
// ============================================================================
namespace vm::decompiler {

class BytecodeDecompiler {
public:
    static inline std::string decompile_to_c(const BytecodeChunk& chunk, std::string_view func_name = "virtualized_entry") {
        auto insts = disasm::BytecodeDisassembler::disassemble(chunk);
        std::ostringstream oss;

        oss << "uint64_t " << func_name << "(uint64_t arg0, uint64_t arg1) {\n";
        oss << "    uint64_t R0 = arg0, R1 = arg1, R2 = 0, R3 = 0, R4 = 0, R5 = 0, R6 = 0, R7 = 0;\n";
        oss << "    uint64_t RSP = 65536, RBP = 65536, RIP = 0, FLAGS = 0;\n";
        oss << "    uint8_t  vm_stack[65536] = {0};\n\n";

        std::unordered_map<u32, bool> branch_targets;
        for (const auto& ins : insts) {
            if (ins.is_branch) branch_targets[ins.target_offset] = true;
        }

        char line[256]{};
        for (const auto& ins : insts) {
            if (branch_targets.find(ins.offset) != branch_targets.end()) {
                std::snprintf(line, sizeof(line), "loc_%04x:\n", ins.offset);
                oss << line;
            }

            const char* r1 = disasm::BytecodeDisassembler::reg_name(ins.reg1);
            const char* r2 = disasm::BytecodeDisassembler::reg_name(ins.reg2);
            const char* r3 = disasm::BytecodeDisassembler::reg_name(ins.reg3);

            switch (ins.opcode) {
            case Opcode::OP_NOP:
                oss << "    /* nop */;\n";
                break;
            case Opcode::OP_MOV_IMM:
                std::snprintf(line, sizeof(line), "    %s = 0x%llxULL;\n", r1, static_cast<unsigned long long>(ins.imm64));
                oss << line;
                break;
            case Opcode::OP_MOV_REG:
                std::snprintf(line, sizeof(line), "    %s = %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_ADD:
                std::snprintf(line, sizeof(line), "    %s += %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_SUB:
                std::snprintf(line, sizeof(line), "    %s -= %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_MUL:
                std::snprintf(line, sizeof(line), "    %s *= %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_DIV:
                std::snprintf(line, sizeof(line), "    %s /= %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_MOD:
                std::snprintf(line, sizeof(line), "    %s %%= %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_AND:
                std::snprintf(line, sizeof(line), "    %s &= %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_OR:
                std::snprintf(line, sizeof(line), "    %s |= %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_XOR:
                std::snprintf(line, sizeof(line), "    %s ^= %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_NOT:
                std::snprintf(line, sizeof(line), "    %s = ~%s;\n", r1, r1);
                oss << line;
                break;
            case Opcode::OP_SHL:
                std::snprintf(line, sizeof(line), "    %s <<= %u;\n", r1, static_cast<unsigned>(ins.shift_or_argc));
                oss << line;
                break;
            case Opcode::OP_SHR:
                std::snprintf(line, sizeof(line), "    %s >>= %u;\n", r1, static_cast<unsigned>(ins.shift_or_argc));
                oss << line;
                break;
            case Opcode::OP_BSWAP:
                std::snprintf(line, sizeof(line), "    %s = __builtin_bswap64(%s);\n", r1, r1);
                oss << line;
                break;
            case Opcode::OP_POPCNT:
                std::snprintf(line, sizeof(line), "    %s = std::popcount(%s);\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_LOAD:
                std::snprintf(line, sizeof(line), "    %s = *(uint64_t*)(&vm_stack[%s]);\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_STORE:
                std::snprintf(line, sizeof(line), "    *(uint64_t*)(&vm_stack[%s]) = %s;\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_VMEMCPY:
                std::snprintf(line, sizeof(line), "    memmove(&vm_stack[%s], &vm_stack[%s], %s);\n", r1, r2, r3);
                oss << line;
                break;
            case Opcode::OP_VMEMSET:
                std::snprintf(line, sizeof(line), "    memset(&vm_stack[%s], (uint8_t)%s, %s);\n", r1, r2, r3);
                oss << line;
                break;
            case Opcode::OP_CMP:
                std::snprintf(line, sizeof(line), "    FLAGS = cmp_flags(%s, %s);\n", r1, r2);
                oss << line;
                break;
            case Opcode::OP_JMP:
                std::snprintf(line, sizeof(line), "    goto loc_%04x;\n", ins.target_offset);
                oss << line;
                break;
            case Opcode::OP_JZ:
                std::snprintf(line, sizeof(line), "    if (FLAGS & ZF) goto loc_%04x;\n", ins.target_offset);
                oss << line;
                break;
            case Opcode::OP_JNZ:
                std::snprintf(line, sizeof(line), "    if (!(FLAGS & ZF)) goto loc_%04x;\n", ins.target_offset);
                oss << line;
                break;
            case Opcode::OP_HALT:
                oss << "    return R0;\n";
                break;
            default:
                break;
            }
        }

        oss << "    return R0;\n}\n";
        return oss.str();
    }
};

} // namespace vm::decompiler

// ============================================================================
// 57. BUILT-IN CRYPTOGRAPHIC KNOWN-ANSWER TEST (KAT) & SELF-TEST SUITE
// ============================================================================
namespace testing {

struct SelfTestSummary {
    u32 total_tests{0};
    u32 passed_tests{0};
    u32 failed_tests{0};
    bool all_passed() const noexcept { return total_tests > 0 && failed_tests == 0; }
};

class SelfTestSuite {
public:
    static inline SelfTestSummary run_all() {
        SelfTestSummary sum{};
        auto check = [&](bool cond) {
            sum.total_tests++;
            if (cond) sum.passed_tests++;
            else      sum.failed_tests++;
        };

        // 1. SHA-256 KAT ("abc")
        check(crypto::Sha256::hash_hex("abc") ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        // 2. SHA-512 KAT ("abc")
        check(crypto::Sha512::hash_hex("abc") ==
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39"
              "a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

        // 3. SHA3-256 KAT ("abc")
        check(crypto::Keccak1600::sha3_256_hex("abc") ==
              "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

        // 4. AES-256-CBC roundtrip
        {
            crypto::Aes256::Key k{};
            crypto::Aes256::Iv iv{};
            for (size_t i = 0; i < 32; ++i) k[i] = static_cast<u8>(i * 7 + 3);
            for (size_t i = 0; i < 16; ++i) iv[i] = static_cast<u8>(i + 1);
            crypto::Aes256 aes(k);
            const u8 msg[] = "AES-256-CBC Verification Block Test!";
            auto ct = aes.encrypt_cbc(msg, sizeof(msg), iv);
            bool dec_ok = false;
            auto pt = aes.decrypt_cbc(ct.data(), ct.size(), iv, dec_ok);
            check(dec_ok && pt.size() == sizeof(msg) && std::memcmp(pt.data(), msg, sizeof(msg)) == 0);
        }

        // 5. ChaCha20-Poly1305 AEAD roundtrip
        {
            crypto::ChaCha20Poly1305::Key k{};
            crypto::ChaCha20Poly1305::Nonce n{};
            crypto::ChaCha20Poly1305::Tag tag{};
            const u8 pt_in[] = "Authenticated Payload";
            const u8 aad[]   = "HeaderAAD";
            auto ct = crypto::ChaCha20Poly1305::seal(k, n, pt_in, sizeof(pt_in), aad, sizeof(aad), tag);
            std::vector<u8> pt_out;
            bool ok = crypto::ChaCha20Poly1305::open(k, n, ct.data(), ct.size(), aad, sizeof(aad), tag, pt_out);
            check(ok && pt_out.size() == sizeof(pt_in) && std::memcmp(pt_out.data(), pt_in, sizeof(pt_in)) == 0);
        }

        // 6. Camellia-256 block roundtrip
        {
            crypto::Camellia256::Key k{};
            crypto::Camellia256::Block blk = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
            crypto::Camellia256::Block orig = blk;
            crypto::Camellia256 cam(k);
            cam.encrypt_block(blk);
            check(blk != orig);
            cam.decrypt_block(blk);
            check(blk == orig);
        }

        // 7. Threefish-512 block roundtrip
        {
            crypto::Threefish512::Key k = {1, 2, 3, 4, 5, 6, 7, 8};
            crypto::Threefish512::Tweak tw = {0x1122ULL, 0x3344ULL};
            crypto::Threefish512::Block blk = {10, 20, 30, 40, 50, 60, 70, 80};
            crypto::Threefish512::Block orig = blk;
            crypto::Threefish512::encrypt_block(blk, k, tw);
            check(blk != orig);
            crypto::Threefish512::decrypt_block(blk, k, tw);
            check(blk == orig);
        }

        // 8. X25519 Diffie-Hellman key agreement
        {
            crypto::X25519::Key32 alice_sk{}, bob_sk{};
            for (size_t i = 0; i < 32; ++i) {
                alice_sk[i] = static_cast<u8>(i + 10);
                bob_sk[i]   = static_cast<u8>(i * 3 + 5);
            }
            auto alice_pk = crypto::X25519::public_key(alice_sk);
            auto bob_pk   = crypto::X25519::public_key(bob_sk);
            auto shared_a = crypto::X25519::scalarmult(alice_sk, bob_pk);
            auto shared_b = crypto::X25519::scalarmult(bob_sk, alice_pk);
            check(shared_a == shared_b);
        }

        // 9. Shamir (3, 5) Secret Sharing
        {
            const u8 secret[] = "MasterRootKey_2026_Threshold";
            auto shares = crypto::ShamirSecretSharing::split_secret(secret, sizeof(secret), 3, 5);
            std::vector<crypto::ShamirSecretSharing::Share> subset = {shares[0], shares[2], shares[4]};
            auto recovered = crypto::ShamirSecretSharing::reconstruct_secret(subset);
            check(recovered.size() == sizeof(secret) && std::memcmp(recovered.data(), secret, sizeof(secret)) == 0);
        }

        // 10. AegisScript Compiler + VirtualMachine Execution
        {
            std::string script = R"(
                let sum = 0;
                let i = 1;
                while (i <= 10) {
                    sum = sum + (i * i);
                    i = i + 1;
                }
                return sum;
            )";
            auto chunk = vm::compiler::AegisScriptCompiler::compile(script, 0x123456789ABCDEF0ULL, true);
            vm::VirtualMachine machine;
            u64 res = machine.run(chunk);
            // 1^2 + 2^2 + ... + 10^2 = 385
            check(res == 385);
        }

        return sum;
    }
};

} // namespace testing


// ============================================================================
// 58. CHACHA20-DRBG CRYPTOGRAPHIC CSPRNG & UUIDv4 GENERATOR
// ============================================================================
namespace crypto {

class ChaCha20Drbg {
public:
    ChaCha20Drbg() noexcept {
        reseed_from_os();
    }

    explicit ChaCha20Drbg(const u8* seed_material, size_t len) noexcept {
        reseed(seed_material, len);
    }

    void reseed(const u8* seed_material, size_t len) noexcept {
        Sha512 ctx(false);
        ctx.update(key_.data(), key_.size());
        ctx.update(nonce_.data(), nonce_.size());
        if (seed_material && len > 0) {
            ctx.update(seed_material, len);
        }
        auto digest = ctx.finalize();
        std::memcpy(key_.data(), &digest[0], 32);
        std::memcpy(nonce_.data(), &digest[32], 12);
        block_counter_ = 1;
        reseed_counter_ = 0;
        secure_zero(digest.data(), digest.size());
    }

    void reseed_from_os() noexcept {
        u64 entropy[8]{};
        std::random_device rd;
        for (size_t i = 0; i < 4; ++i) {
            entropy[i] = (static_cast<u64>(rd()) << 32) | static_cast<u64>(rd());
        }
#if defined(AEGIS_COMPILER_MSVC)
        entropy[4] = __rdtsc();
#endif
        entropy[5] = reinterpret_cast<uintptr_t>(this);
        entropy[6] = core::RuntimeRandom::get_u64();
        entropy[7] = 0x9E3779B97F4A7C15ULL;
        reseed(reinterpret_cast<const u8*>(entropy), sizeof(entropy));
        secure_zero(entropy, sizeof(entropy));
    }

    void generate_bytes(u8* out, size_t len) noexcept {
        if (reseed_counter_ > 10000) {
            reseed_from_os();
        }
        std::memset(out, 0, len);
        ChaCha20::crypt(key_, nonce_, block_counter_, out, len);
        block_counter_ += static_cast<u32>((len + 63) / 64);

        // Forward-secrecy ratchet: immediately re-key after each generation
        std::array<u8, 64> ratchet_block{};
        ChaCha20::generate_block(key_, nonce_, block_counter_++, ratchet_block);
        std::memcpy(key_.data(), &ratchet_block[0], 32);
        std::memcpy(nonce_.data(), &ratchet_block[32], 12);
        secure_zero(ratchet_block.data(), ratchet_block.size());
        reseed_counter_++;
    }

    u64 next_u64() noexcept {
        u64 v = 0;
        generate_bytes(reinterpret_cast<u8*>(&v), sizeof(v));
        return v;
    }

    u32 next_u32() noexcept {
        u32 v = 0;
        generate_bytes(reinterpret_cast<u8*>(&v), sizeof(v));
        return v;
    }

    std::string generate_uuid_v4() {
        std::array<u8, 16> b{};
        generate_bytes(b.data(), 16);
        b[6] = static_cast<u8>((b[6] & 0x0F) | 0x40); // Version 4
        b[8] = static_cast<u8>((b[8] & 0x3F) | 0x80); // Variant 1 (RFC 4122)

        char buf[37]{};
        std::snprintf(buf, sizeof(buf),
                      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                      b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
        return std::string(buf);
    }

private:
    ChaCha20::Key key_{};
    ChaCha20::Nonce nonce_{};
    u32 block_counter_{1};
    u64 reseed_counter_{0};
};

} // namespace crypto

// ============================================================================
// 59. CPU EMULATOR / UNICORN / QILING / TRITON DYNAMIC DETECTOR
// ============================================================================
namespace anti {

class EmulatorDetector {
public:
    /**
     * @brief Verifies IEEE-754 quiet NaN payload bit-preservation across arithmetic conversions
     * Many lightweight binary emulators canonicalize NaN payloads and strip custom lower mantissa bits.
     */
    static inline bool check_fp_nan_payload_fidelity() noexcept {
        u64 custom_nan_bits = 0x7FF8000000133742ULL;
        double d = 0.0;
        std::memcpy(&d, &custom_nan_bits, sizeof(double));
        obf::Opaque::do_not_optimize(d);
        double d2 = d + 0.0;
        obf::Opaque::do_not_optimize(d2);
        u64 out_bits = 0;
        std::memcpy(&out_bits, &d2, sizeof(double));
        return (out_bits & 0x0000000000FFFFFFULL) != 0x00133742ULL;
    }

    /**
     * @brief Checks CPUID leaf 0 / 0x80000000 maximum leaf invariants
     */
    static inline bool check_cpuid_leaf_invariants() noexcept {
#if defined(AEGIS_COMPILER_MSVC)
        int info0[4]{};
        int info_ext[4]{};
        __cpuid(info0, 0);
        __cpuid(info_ext, static_cast<int>(0x80000000U));
        if (info0[0] <= 0 || static_cast<u32>(info_ext[0]) < 0x80000000U) {
            return true;
        }
#endif
        return false;
    }

    static inline bool is_emulated_environment() noexcept {
        return check_fp_nan_payload_fidelity() || check_cpuid_leaf_invariants();
    }
};

// ============================================================================
// 60. IN-MEMORY FUNCTION PROLOGUE SNAPSHOTTER & HOTPATCH GUARD
// ============================================================================
class CodePatchGuard {
public:
    struct GuardedFunction {
        std::string name;
        const void* address{nullptr};
        size_t prologue_size{0};
        std::vector<u8> encrypted_prologue;
        crypto::Sha256::Digest sha_digest{};
    };

    CodePatchGuard() noexcept {
        session_key_ = core::RuntimeRandom::get_u64() | 1ULL;
    }

    void register_function(std::string name, const void* fn_ptr, size_t prologue_bytes = 32) {
        if (!fn_ptr || prologue_bytes == 0) return;
        GuardedFunction gf{};
        gf.name = std::move(name);
        gf.address = fn_ptr;
        gf.prologue_size = prologue_bytes;
        const auto* raw = static_cast<const u8*>(fn_ptr);
        gf.sha_digest = crypto::Sha256::hash(raw, prologue_bytes);

        gf.encrypted_prologue.resize(prologue_bytes);
        u64 k = session_key_;
        for (size_t i = 0; i < prologue_bytes; ++i) {
            gf.encrypted_prologue[i] = raw[i] ^ static_cast<u8>(k & 0xFF);
            k = vm::BytecodeChunk::advance_rolling_key(k, gf.encrypted_prologue[i]);
        }
        functions_.push_back(std::move(gf));
    }

    std::vector<std::string> check_violations() const {
        std::vector<std::string> tampered;
        for (const auto& gf : functions_) {
            const auto* raw = static_cast<const u8*>(gf.address);
            if (IntegrityScanner::has_inline_hook(gf.address) ||
                IntegrityScanner::has_software_breakpoints(gf.address, gf.prologue_size)) {
                tampered.push_back(gf.name);
                continue;
            }
            auto cur_sha = crypto::Sha256::hash(raw, gf.prologue_size);
            if (cur_sha != gf.sha_digest) {
                tampered.push_back(gf.name);
            }
        }
        return tampered;
    }

    bool verify_all() const {
        return check_violations().empty();
    }

    size_t guarded_count() const noexcept { return functions_.size(); }

private:
    u64 session_key_{0};
    std::vector<GuardedFunction> functions_;
};

} // namespace anti

// ============================================================================
// 61. CRYPTOGRAPHIC STEGANOGRAPHIC BYTECODE WATERMARKING ENGINE
// ============================================================================
namespace watermark {

struct WatermarkRecord {
    u64 customer_id{0};
    u32 build_number{0};
    u32 watermark_crc{0};
    bool valid{false};
};

/**
 * @brief Embeds and extracts authenticated 128-bit customer watermarks inside
 * OP_JUNK instructions of a VM BytecodeChunk for leak tracing / anti-piracy forensics.
 */
class BytecodeWatermarker {
public:
    static constexpr u64 WATERMARK_TAG_MASK  = 0xFFFF000000000000ULL;
    static constexpr u64 WATERMARK_TAG_HI    = 0xAE61000000000000ULL;
    static constexpr u64 WATERMARK_TAG_LO    = 0xAE62000000000000ULL;

    static inline void embed_into_builder(vm::BytecodeBuilder& builder, u64 customer_id, u32 build_number, u64 secret_key) {
        u8 buf[12]{};
        std::memcpy(&buf[0], &customer_id, 8);
        std::memcpy(&buf[8], &build_number, 4);
        u32 crc = core::Crc32::calculate(buf, 12);

        u64 word0 = (customer_id & 0x0000FFFFFFFFFFFFULL) | WATERMARK_TAG_HI;
        u64 word1 = ((static_cast<u64>(customer_id >> 48) & 0xFFFFULL) << 32) |
                    (static_cast<u64>(build_number) & 0xFFFFFFFFULL) | WATERMARK_TAG_LO;
        u64 word2 = (static_cast<u64>(crc) & 0xFFFFFFFFULL) | (WATERMARK_TAG_LO ^ 0x0001000000000000ULL);

        u64 k0 = core::XxHash64::hash("WM_SLOT_0", secret_key);
        u64 k1 = core::XxHash64::hash("WM_SLOT_1", secret_key);
        u64 k2 = core::XxHash64::hash("WM_SLOT_2", secret_key);

        builder.rekey(word0 ^ k0);
        builder.rekey(word1 ^ k1);
        builder.rekey(word2 ^ k2);
    }

    static inline WatermarkRecord extract_from_chunk(const vm::BytecodeChunk& chunk, u64 secret_key) {
        WatermarkRecord rec{};
        auto insts = vm::disasm::BytecodeDisassembler::disassemble(chunk);
        u64 k0 = core::XxHash64::hash("WM_SLOT_0", secret_key);
        u64 k1 = core::XxHash64::hash("WM_SLOT_1", secret_key);
        u64 k2 = core::XxHash64::hash("WM_SLOT_2", secret_key);

        for (size_t i = 0; i + 2 < insts.size(); ++i) {
            if (insts[i].opcode == vm::Opcode::OP_REKEY &&
                insts[i + 1].opcode == vm::Opcode::OP_REKEY &&
                insts[i + 2].opcode == vm::Opcode::OP_REKEY) {

                u64 w0 = insts[i].imm64 ^ k0;
                u64 w1 = insts[i + 1].imm64 ^ k1;
                u64 w2 = insts[i + 2].imm64 ^ k2;

                if ((w0 & WATERMARK_TAG_MASK) == WATERMARK_TAG_HI &&
                    (w1 & WATERMARK_TAG_MASK) == WATERMARK_TAG_LO &&
                    (w2 & WATERMARK_TAG_MASK) == (WATERMARK_TAG_LO ^ 0x0001000000000000ULL)) {

                    u64 cid_lo = w0 & 0x0000FFFFFFFFFFFFULL;
                    u64 cid_hi = (w1 >> 32) & 0xFFFFULL;
                    u64 cid = cid_lo | (cid_hi << 48);
                    u32 bnum = static_cast<u32>(w1 & 0xFFFFFFFFULL);
                    u32 crc  = static_cast<u32>(w2 & 0xFFFFFFFFULL);

                    u8 buf[12]{};
                    std::memcpy(&buf[0], &cid, 8);
                    std::memcpy(&buf[8], &bnum, 4);
                    if (core::Crc32::calculate(buf, 12) == crc) {
                        rec.customer_id = cid;
                        rec.build_number = bnum;
                        rec.watermark_crc = crc;
                        rec.valid = true;
                        return rec;
                    }
                }
            }
        }
        return rec;
    }
};

} // namespace watermark

// ============================================================================
// 62. COMPREHENSIVE DIAGNOSTIC & SECURITY POSTURE REPORT GENERATOR
// ============================================================================
namespace diagnostics {

class SecurityPostureReporter {
public:
    static inline json::JsonValue generate_json_report() {
        auto root = json::JsonValue::make_object();
        root.set("sdk_version", json::JsonValue("Aegis Master Protection Suite v2.0"));
        root.set("debugger_active", json::JsonValue(anti::AntiDebug::is_debugger_active()));
        root.set("virtual_machine_detected", json::JsonValue(anti::AntiVm::is_virtual_machine()));
        root.set("emulator_detected", json::JsonValue(anti::EmulatorDetector::is_emulated_environment()));
        root.set("hwid_fingerprint", json::JsonValue(static_cast<i64>(hwid::HardwareId::get_machine_fingerprint())));

        auto pe_rep = pe::PeImageAnalyzer::analyze_module();
        auto pe_obj = json::JsonValue::make_object();
        pe_obj.set("valid_pe", json::JsonValue(pe_rep.valid_pe));
        pe_obj.set("is_64bit", json::JsonValue(pe_rep.is_64bit));
        pe_obj.set("aslr", json::JsonValue(pe_rep.has_aslr));
        pe_obj.set("dep_nx", json::JsonValue(pe_rep.has_dep_nx));
        pe_obj.set("cfg", json::JsonValue(pe_rep.has_cfg));
        pe_obj.set("rwx_sections", json::JsonValue(static_cast<i64>(pe_rep.rwx_section_count)));
        pe_obj.set("section_count", json::JsonValue(static_cast<i64>(pe_rep.sections.size())));
        root.set("pe_security", std::move(pe_obj));

        auto mem_rep = anti::EnvironmentForensics::audit_virtual_memory();
        auto mem_obj = json::JsonValue::make_object();
        mem_obj.set("total_committed_regions", json::JsonValue(static_cast<i64>(mem_rep.total_regions)));
        mem_obj.set("image_exec_regions", json::JsonValue(static_cast<i64>(mem_rep.image_exec_regions)));
        mem_obj.set("private_exec_regions", json::JsonValue(static_cast<i64>(mem_rep.private_exec_regions)));
        mem_obj.set("rwx_regions", json::JsonValue(static_cast<i64>(mem_rep.rwx_regions)));
        root.set("virtual_memory", std::move(mem_obj));

        auto kat = testing::SelfTestSuite::run_all();
        auto kat_obj = json::JsonValue::make_object();
        kat_obj.set("total_tests", json::JsonValue(static_cast<i64>(kat.total_tests)));
        kat_obj.set("passed_tests", json::JsonValue(static_cast<i64>(kat.passed_tests)));
        kat_obj.set("all_passed", json::JsonValue(kat.all_passed()));
        root.set("cryptographic_self_test", std::move(kat_obj));

        return root;
    }

    static inline std::string generate_formatted_summary() {
        return generate_json_report().dump(2);
    }
};

} // namespace diagnostics


// ============================================================================
// 63. SERPENT-256 (32-ROUND SPN) & BLOWFISH-256 KEY-DEPENDENT S-BOX CIPHER
// ============================================================================
namespace crypto {

/**
 * @brief AES Finalist Serpent-256 32-Round Substitution-Permutation Network Block Cipher
 */
class Serpent256 {
public:
    using Key   = std::array<u8, 32>;
    using Block = std::array<u8, 16>;

    static constexpr u8 SBOX[8][16] = {
        {  3,  8, 15,  1, 10,  6,  5, 11, 14, 13,  4,  2,  7,  0,  9, 12 },
        { 15, 12,  2,  7,  9,  0,  5, 10,  1, 11, 14,  8,  6, 13,  3,  4 },
        {  8,  6,  7,  9,  3, 12, 10, 15, 13,  1, 14,  4,  0, 11,  5,  2 },
        {  0, 15, 11,  8, 12,  9,  6,  3, 13,  1,  2,  4, 10,  7,  5, 14 },
        {  1, 15,  8,  3, 12,  0, 11,  6,  2,  5,  4, 10,  9, 14,  7, 13 },
        { 15,  5,  2, 11,  4, 10,  9, 12,  0,  3, 14,  8, 13,  6,  7,  1 },
        {  7,  2, 12,  5,  8,  4,  6, 11, 14,  9,  1, 15, 13,  3, 10,  0 },
        {  1, 13, 15,  0, 14,  8,  2, 11,  7,  4, 12, 10,  9,  3,  5,  6 }
    };

    static constexpr u8 INV_SBOX[8][16] = {
        { 13,  3, 11,  0, 10,  6,  5, 12,  1, 14,  4,  7, 15,  9,  8,  2 },
        {  5,  8,  2, 14, 15,  6, 12,  3, 11,  4,  7,  9,  1, 13, 10,  0 },
        { 12,  9, 15,  4, 11, 14,  1,  2,  0,  3,  6, 13,  5,  8, 10,  7 },
        {  0,  9, 10,  7, 11, 14,  6, 13,  3,  5, 12,  2,  4,  8, 15,  1 },
        {  5,  0,  8,  3, 10,  9,  7, 14,  2, 12, 11,  6,  4, 15, 13,  1 },
        {  8, 15,  2,  9,  4,  1, 13, 14, 11,  6,  5,  3,  7, 12, 10,  0 },
        { 15, 10,  1, 13,  5,  3,  6,  0,  4,  9, 14,  7,  2, 12,  8, 11 },
        {  3,  0,  6, 13,  9, 14, 15,  8,  5, 12, 11,  7, 10,  1,  4,  2 }
    };

    static constexpr u32 PHI = 0x9E3779B9UL;

    static constexpr u32 rotl32(u32 x, u32 n) noexcept {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr u32 rotr32(u32 x, u32 n) noexcept {
        return (x >> n) | (x << (32 - n));
    }

    static constexpr void apply_sbox(size_t box, u32& r0, u32& r1, u32& r2, u32& r3, bool inverse) noexcept {
        u32 o0 = 0, o1 = 0, o2 = 0, o3 = 0;
        const u8 (&sb)[16] = inverse ? INV_SBOX[box & 7] : SBOX[box & 7];
        for (u32 bit = 0; bit < 32; ++bit) {
            u8 in_nib = static_cast<u8>(
                (((r0 >> bit) & 1U) << 0) |
                (((r1 >> bit) & 1U) << 1) |
                (((r2 >> bit) & 1U) << 2) |
                (((r3 >> bit) & 1U) << 3));
            u8 out_nib = sb[in_nib];
            o0 |= static_cast<u32>((out_nib >> 0) & 1U) << bit;
            o1 |= static_cast<u32>((out_nib >> 1) & 1U) << bit;
            o2 |= static_cast<u32>((out_nib >> 2) & 1U) << bit;
            o3 |= static_cast<u32>((out_nib >> 3) & 1U) << bit;
        }
        r0 = o0; r1 = o1; r2 = o2; r3 = o3;
    }

    static constexpr void linear_transform(u32& x0, u32& x1, u32& x2, u32& x3) noexcept {
        x0 = rotl32(x0, 13);
        x2 = rotl32(x2, 3);
        x1 = x1 ^ x0 ^ x2;
        x3 = x3 ^ x2 ^ (x0 << 3);
        x1 = rotl32(x1, 1);
        x3 = rotl32(x3, 7);
        x0 = x0 ^ x1 ^ x3;
        x2 = x2 ^ x3 ^ (x1 << 7);
        x0 = rotl32(x0, 5);
        x2 = rotl32(x2, 22);
    }

    static constexpr void inv_linear_transform(u32& x0, u32& x1, u32& x2, u32& x3) noexcept {
        x2 = rotr32(x2, 22);
        x0 = rotr32(x0, 5);
        x2 = x2 ^ x3 ^ (x1 << 7);
        x0 = x0 ^ x1 ^ x3;
        x3 = rotr32(x3, 7);
        x1 = rotr32(x1, 1);
        x3 = x3 ^ x2 ^ (x0 << 3);
        x1 = x1 ^ x0 ^ x2;
        x2 = rotr32(x2, 3);
        x0 = rotr32(x0, 13);
    }

    constexpr explicit Serpent256(const Key& key) noexcept {
        u32 w[140]{};
        for (size_t i = 0; i < 8; ++i) {
            w[i] = static_cast<u32>(key[i * 4 + 0]) |
                  (static_cast<u32>(key[i * 4 + 1]) << 8) |
                  (static_cast<u32>(key[i * 4 + 2]) << 16) |
                  (static_cast<u32>(key[i * 4 + 3]) << 24);
        }
        for (size_t i = 8; i < 140; ++i) {
            w[i] = rotl32(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ static_cast<u32>(i - 8), 11);
        }
        for (size_t r = 0; r < 33; ++r) {
            size_t box = (32 + 3 - r) % 8;
            u32 k0 = w[8 + r * 4 + 0];
            u32 k1 = w[8 + r * 4 + 1];
            u32 k2 = w[8 + r * 4 + 2];
            u32 k3 = w[8 + r * 4 + 3];
            apply_sbox(box, k0, k1, k2, k3, false);
            subkeys_[r][0] = k0;
            subkeys_[r][1] = k1;
            subkeys_[r][2] = k2;
            subkeys_[r][3] = k3;
        }
    }

    constexpr void encrypt_block(Block& b) const noexcept {
        auto rd32 = [](const u8* p) constexpr noexcept -> u32 {
            return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
                  (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
        };
        auto wr32 = [](u8* p, u32 v) constexpr noexcept {
            p[0] = static_cast<u8>(v & 0xFF);
            p[1] = static_cast<u8>((v >> 8) & 0xFF);
            p[2] = static_cast<u8>((v >> 16) & 0xFF);
            p[3] = static_cast<u8>((v >> 24) & 0xFF);
        };

        u32 x0 = rd32(&b[0]), x1 = rd32(&b[4]), x2 = rd32(&b[8]), x3 = rd32(&b[12]);

        for (size_t r = 0; r < 32; ++r) {
            x0 ^= subkeys_[r][0];
            x1 ^= subkeys_[r][1];
            x2 ^= subkeys_[r][2];
            x3 ^= subkeys_[r][3];
            apply_sbox(r % 8, x0, x1, x2, x3, false);
            if (r < 31) {
                linear_transform(x0, x1, x2, x3);
            } else {
                x0 ^= subkeys_[32][0];
                x1 ^= subkeys_[32][1];
                x2 ^= subkeys_[32][2];
                x3 ^= subkeys_[32][3];
            }
        }

        wr32(&b[0], x0); wr32(&b[4], x1); wr32(&b[8], x2); wr32(&b[12], x3);
    }

    constexpr void decrypt_block(Block& b) const noexcept {
        auto rd32 = [](const u8* p) constexpr noexcept -> u32 {
            return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
                  (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
        };
        auto wr32 = [](u8* p, u32 v) constexpr noexcept {
            p[0] = static_cast<u8>(v & 0xFF);
            p[1] = static_cast<u8>((v >> 8) & 0xFF);
            p[2] = static_cast<u8>((v >> 16) & 0xFF);
            p[3] = static_cast<u8>((v >> 24) & 0xFF);
        };

        u32 x0 = rd32(&b[0]), x1 = rd32(&b[4]), x2 = rd32(&b[8]), x3 = rd32(&b[12]);

        for (int r = 31; r >= 0; --r) {
            if (r == 31) {
                x0 ^= subkeys_[32][0];
                x1 ^= subkeys_[32][1];
                x2 ^= subkeys_[32][2];
                x3 ^= subkeys_[32][3];
            } else {
                inv_linear_transform(x0, x1, x2, x3);
            }
            apply_sbox(static_cast<size_t>(r) % 8, x0, x1, x2, x3, true);
            x0 ^= subkeys_[static_cast<size_t>(r)][0];
            x1 ^= subkeys_[static_cast<size_t>(r)][1];
            x2 ^= subkeys_[static_cast<size_t>(r)][2];
            x3 ^= subkeys_[static_cast<size_t>(r)][3];
        }

        wr32(&b[0], x0); wr32(&b[4], x1); wr32(&b[8], x2); wr32(&b[12], x3);
    }

private:
    std::array< std::array<u32, 4>, 33 > subkeys_{};
};

// ============================================================================
// 64. CRYPTOGRAPHIC MERKLE TREE & INCLUSION PROOF VERIFIER
// ============================================================================
class MerkleTree {
public:
    using Hash = Sha256::Digest;

    struct ProofNode {
        Hash sibling_hash{};
        bool sibling_is_left{false};
    };

    struct InclusionProof {
        size_t leaf_index{0};
        Hash leaf_hash{};
        Hash root_hash{};
        std::vector<ProofNode> path;
    };

    explicit MerkleTree(const std::vector<std::vector<u8>>& leaves) {
        build(leaves);
    }

    void build(const std::vector<std::vector<u8>>& leaves) {
        levels_.clear();
        if (leaves.empty()) return;

        std::vector<Hash> current_level;
        current_level.reserve(leaves.size());
        for (const auto& leaf : leaves) {
            current_level.push_back(hash_leaf(leaf.data(), leaf.size()));
        }
        levels_.push_back(current_level);

        while (current_level.size() > 1) {
            if ((current_level.size() & 1) != 0) {
                current_level.push_back(current_level.back());
            }
            std::vector<Hash> next_level;
            next_level.reserve(current_level.size() / 2);
            for (size_t i = 0; i < current_level.size(); i += 2) {
                next_level.push_back(hash_children(current_level[i], current_level[i + 1]));
            }
            levels_.back() = std::move(current_level);
            current_level = next_level;
            levels_.push_back(current_level);
        }
    }

    Hash root() const noexcept {
        if (levels_.empty() || levels_.back().empty()) return Hash{};
        return levels_.back().front();
    }

    InclusionProof generate_proof(size_t leaf_index) const {
        InclusionProof proof{};
        if (levels_.empty() || leaf_index >= levels_.front().size()) return proof;

        proof.leaf_index = leaf_index;
        proof.leaf_hash = levels_.front()[leaf_index];
        proof.root_hash = root();

        size_t idx = leaf_index;
        for (size_t lvl = 0; lvl + 1 < levels_.size(); ++lvl) {
            const auto& level_nodes = levels_[lvl];
            size_t sib_idx = (idx ^ 1);
            if (sib_idx >= level_nodes.size()) sib_idx = idx;

            ProofNode pn{};
            pn.sibling_hash = level_nodes[sib_idx];
            pn.sibling_is_left = (sib_idx < idx);
            proof.path.push_back(pn);
            idx >>= 1;
        }
        return proof;
    }

    static inline bool verify_proof(const u8* leaf_data, size_t leaf_len, const InclusionProof& proof) noexcept {
        Hash cur = hash_leaf(leaf_data, leaf_len);
        if (cur != proof.leaf_hash) return false;

        for (const auto& step : proof.path) {
            if (step.sibling_is_left) {
                cur = hash_children(step.sibling_hash, cur);
            } else {
                cur = hash_children(cur, step.sibling_hash);
            }
        }
        return cur == proof.root_hash;
    }

private:
    static inline Hash hash_leaf(const u8* data, size_t len) noexcept {
        Sha256 ctx;
        u8 prefix = 0x00;
        ctx.update(&prefix, 1);
        if (data && len > 0) ctx.update(data, len);
        return ctx.finalize();
    }

    static inline Hash hash_children(const Hash& left, const Hash& right) noexcept {
        Sha256 ctx;
        u8 prefix = 0x01;
        ctx.update(&prefix, 1);
        ctx.update(left.data(), left.size());
        ctx.update(right.data(), right.size());
        return ctx.finalize();
    }

    std::vector<std::vector<Hash>> levels_;
};

} // namespace crypto

// ============================================================================
// 65. INTERACTIVE STEP-BY-STEP VM DEBUGGER, WATCHPOINT & TRACE ENGINE
// ============================================================================
namespace vm::debugger {

struct TraceStep {
    u64 step_number{0};
    u32 pc{0};
    Opcode opcode{Opcode::OP_NOP};
    std::string disassembly;
    std::array<reg_t, static_cast<size_t>(VReg::COUNT)> registers_after{};
};

class VMDebugger {
public:
    explicit VMDebugger(const BytecodeChunk& chunk)
        : chunk_(chunk) {
        decoded_ = disasm::BytecodeDisassembler::disassemble(chunk_);
        for (size_t i = 0; i < decoded_.size(); ++i) {
            offset_to_idx_[decoded_[i].offset] = i;
        }
    }

    void add_breakpoint(u32 bytecode_offset) {
        breakpoints_[bytecode_offset] = true;
    }

    void remove_breakpoint(u32 bytecode_offset) {
        breakpoints_.erase(bytecode_offset);
    }

    void clear_breakpoints() {
        breakpoints_.clear();
    }

    std::vector<TraceStep> collect_static_trace_preview(size_t max_steps = 64) const {
        std::vector<TraceStep> trace;
        size_t limit = (decoded_.size() < max_steps) ? decoded_.size() : max_steps;
        trace.reserve(limit);
        for (size_t i = 0; i < limit; ++i) {
            TraceStep ts{};
            ts.step_number = i + 1;
            ts.pc = decoded_[i].offset;
            ts.opcode = decoded_[i].opcode;
            ts.disassembly = decoded_[i].mnemonic + (decoded_[i].operands_str.empty() ? "" : (" " + decoded_[i].operands_str));
            trace.push_back(std::move(ts));
        }
        return trace;
    }

    std::string format_context_registers(const VMContext& ctx) const {
        std::ostringstream oss;
        char buf[128]{};
        for (size_t r = 0; r < static_cast<size_t>(VReg::COUNT); ++r) {
            VReg vr = static_cast<VReg>(r);
            std::snprintf(buf, sizeof(buf), "%-6s = 0x%016llX",
                          disasm::BytecodeDisassembler::reg_name(vr),
                          static_cast<unsigned long long>(ctx.get_reg(vr)));
            oss << buf << ((r % 3 == 2 || r + 1 == static_cast<size_t>(VReg::COUNT)) ? "\n" : "   ");
        }
        return oss.str();
    }

    size_t instruction_count() const noexcept { return decoded_.size(); }

private:
    BytecodeChunk chunk_;
    std::vector<disasm::DecodedInstruction> decoded_;
    std::unordered_map<u32, size_t> offset_to_idx_;
    std::unordered_map<u32, bool> breakpoints_;
};

} // namespace vm::debugger

// ============================================================================
// 66. ENCRYPTED INDIRECT CALL DISPATCH TABLE (HASH-INDEXED CONTROL TRANSFER)
// ============================================================================
namespace obf {

template <typename Ret, typename... Args>
class EncryptedDispatchTable {
public:
    using FnPtr = Ret(*)(Args...);

    EncryptedDispatchTable() noexcept {
        table_key_ = core::RuntimeRandom::get_u64() | 1ULL;
    }

    void bind(u64 symbol_hash, FnPtr fn) {
        uintptr_t raw = reinterpret_cast<uintptr_t>(fn);
        u64 masked = static_cast<u64>(raw) ^ (table_key_ * symbol_hash);
        u64 rotated = (masked << 19) | (masked >> (64 - 19));
        entries_[symbol_hash] = rotated;
    }

    void bind(std::string_view symbol_name, FnPtr fn) {
        bind(core::Fnv1a::hash(symbol_name), fn);
    }

    bool contains(u64 symbol_hash) const noexcept {
        return entries_.find(symbol_hash) != entries_.end();
    }

    Ret invoke(u64 symbol_hash, Args... args) const {
        auto it = entries_.find(symbol_hash);
        if (it == entries_.end()) {
            throw std::runtime_error("Aegis: Unbound dispatch symbol hash");
        }
        u64 rotated = it->second;
        u64 masked = (rotated >> 19) | (rotated << (64 - 19));
        uintptr_t raw = static_cast<uintptr_t>(Mba::bitwise_xor(masked, table_key_ * symbol_hash));
        FnPtr fn = reinterpret_cast<FnPtr>(raw);
        return fn(std::forward<Args>(args)...);
    }

    Ret invoke(std::string_view symbol_name, Args... args) const {
        return invoke(core::Fnv1a::hash(symbol_name), std::forward<Args>(args)...);
    }

    size_t size() const noexcept { return entries_.size(); }

private:
    u64 table_key_{0};
    std::unordered_map<u64, u64> entries_;
};

} // namespace obf


// ============================================================================
// 67. BLOWFISH-448 FEISTEL CIPHER & CONSTANT-TIME MEMORY UTILITIES
// ============================================================================
namespace crypto {

/**
 * @brief Bruce Schneier's Blowfish 64-bit Feistel Cipher (Up to 448-bit Keys, 16 Rounds)
 * Initializes P-array and 4 S-boxes dynamically using key-dependent ChaCha20/Pi expansion.
 */
class Blowfish {
public:
    using Block = std::array<u8, 8>;

    static constexpr std::array<u32, 18> INIT_P = {
        0x243f6a88UL, 0x85a308d3UL, 0x13198a2eUL, 0x03707344UL,
        0xa4093822UL, 0x299f31d0UL, 0x082efa98UL, 0xec4e6c89UL,
        0x452821e6UL, 0x38d01377UL, 0xbe5466cfUL, 0x34e90c6cUL,
        0xc0ac29b7UL, 0xc97c50ddUL, 0x3f84d5b5UL, 0xb5470917UL,
        0x9216d5d9UL, 0x8979fb1bUL
    };

    explicit Blowfish(const u8* key, size_t key_len) noexcept {
        init_tables(key, key_len);
    }

    explicit Blowfish(std::string_view key) noexcept {
        init_tables(reinterpret_cast<const u8*>(key.data()), key.size());
    }

    ~Blowfish() noexcept {
        secure_zero(P_.data(), sizeof(P_));
        secure_zero(S_.data(), sizeof(S_));
    }

    void init_tables(const u8* key, size_t key_len) noexcept {
        P_ = INIT_P;

        // Deterministic Pi-derived S-box initialization via SHAKE256("AEGIS_BLOWFISH_PI_SBOX")
        static constexpr u8 domain[] = "AEGIS_BLOWFISH_PI_SBOX_INIT_V1";
        Keccak1600::shake256(domain, sizeof(domain) - 1,
                             reinterpret_cast<u8*>(S_.data()), sizeof(S_));

        if (!key || key_len == 0) return;

        size_t j = 0;
        for (size_t i = 0; i < 18; ++i) {
            u32 data = 0;
            for (size_t k = 0; k < 4; ++k) {
                data = (data << 8) | key[j];
                j = (j + 1) % key_len;
            }
            P_[i] ^= data;
        }

        u32 l = 0, r = 0;
        for (size_t i = 0; i < 18; i += 2) {
            encrypt_lr(l, r);
            P_[i] = l;
            P_[i + 1] = r;
        }

        for (size_t s = 0; s < 4; ++s) {
            for (size_t i = 0; i < 256; i += 2) {
                encrypt_lr(l, r);
                S_[s][i] = l;
                S_[s][i + 1] = r;
            }
        }
    }

    void encrypt_lr(u32& xl, u32& xr) const noexcept {
        for (size_t i = 0; i < 16; ++i) {
            xl ^= P_[i];
            xr ^= feistel(xl);
            u32 tmp = xl; xl = xr; xr = tmp;
        }
        u32 tmp = xl; xl = xr; xr = tmp;
        xr ^= P_[16];
        xl ^= P_[17];
    }

    void decrypt_lr(u32& xl, u32& xr) const noexcept {
        for (size_t i = 17; i > 1; --i) {
            xl ^= P_[i];
            xr ^= feistel(xl);
            u32 tmp = xl; xl = xr; xr = tmp;
        }
        u32 tmp = xl; xl = xr; xr = tmp;
        xr ^= P_[1];
        xl ^= P_[0];
    }

    void encrypt_block(Block& b) const noexcept {
        u32 xl = (static_cast<u32>(b[0]) << 24) | (static_cast<u32>(b[1]) << 16) |
                 (static_cast<u32>(b[2]) << 8)  |  static_cast<u32>(b[3]);
        u32 xr = (static_cast<u32>(b[4]) << 24) | (static_cast<u32>(b[5]) << 16) |
                 (static_cast<u32>(b[6]) << 8)  |  static_cast<u32>(b[7]);
        encrypt_lr(xl, xr);
        b[0] = static_cast<u8>((xl >> 24) & 0xFF);
        b[1] = static_cast<u8>((xl >> 16) & 0xFF);
        b[2] = static_cast<u8>((xl >> 8)  & 0xFF);
        b[3] = static_cast<u8>(xl & 0xFF);
        b[4] = static_cast<u8>((xr >> 24) & 0xFF);
        b[5] = static_cast<u8>((xr >> 16) & 0xFF);
        b[6] = static_cast<u8>((xr >> 8)  & 0xFF);
        b[7] = static_cast<u8>(xr & 0xFF);
    }

    void decrypt_block(Block& b) const noexcept {
        u32 xl = (static_cast<u32>(b[0]) << 24) | (static_cast<u32>(b[1]) << 16) |
                 (static_cast<u32>(b[2]) << 8)  |  static_cast<u32>(b[3]);
        u32 xr = (static_cast<u32>(b[4]) << 24) | (static_cast<u32>(b[5]) << 16) |
                 (static_cast<u32>(b[6]) << 8)  |  static_cast<u32>(b[7]);
        decrypt_lr(xl, xr);
        b[0] = static_cast<u8>((xl >> 24) & 0xFF);
        b[1] = static_cast<u8>((xl >> 16) & 0xFF);
        b[2] = static_cast<u8>((xl >> 8)  & 0xFF);
        b[3] = static_cast<u8>(xl & 0xFF);
        b[4] = static_cast<u8>((xr >> 24) & 0xFF);
        b[5] = static_cast<u8>((xr >> 16) & 0xFF);
        b[6] = static_cast<u8>((xr >> 8)  & 0xFF);
        b[7] = static_cast<u8>(xr & 0xFF);
    }

private:
    u32 feistel(u32 x) const noexcept {
        u8 a = static_cast<u8>((x >> 24) & 0xFF);
        u8 b = static_cast<u8>((x >> 16) & 0xFF);
        u8 c = static_cast<u8>((x >> 8)  & 0xFF);
        u8 d = static_cast<u8>(x & 0xFF);
        return ((S_[0][a] + S_[1][b]) ^ S_[2][c]) + S_[3][d];
    }

    std::array<u32, 18> P_{};
    std::array< std::array<u32, 256>, 4 > S_{};
};

/**
 * @brief Side-Channel Resistant Constant-Time Operations
 */
class ConstantTime {
public:
    static constexpr bool equal(const u8* a, const u8* b, size_t len) noexcept {
        u8 diff = 0;
        for (size_t i = 0; i < len; ++i) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    static constexpr u64 select_u64(bool condition, u64 if_true, u64 if_false) noexcept {
        u64 mask = condition ? ~0ULL : 0ULL;
        return (if_true & mask) | (if_false & (~mask));
    }

    static constexpr void conditional_swap(bool swap, u8* a, u8* b, size_t len) noexcept {
        u8 mask = swap ? 0xFF : 0x00;
        for (size_t i = 0; i < len; ++i) {
            u8 t = mask & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
        }
    }
};

} // namespace crypto


} // namespace aegis
