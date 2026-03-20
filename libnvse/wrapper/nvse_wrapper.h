#pragma once
// Wrapper header for xNVSE bindings
// Used by bindgen to generate Rust FFI bindings.
// Works with both i686-pc-windows-gnu (MinGW) and i686-pc-windows-msvc targets.

// ---------------------------------------------------------------------------
// Minimal C++ stdlib stubs (provided in wrapper/include/)
// ---------------------------------------------------------------------------
#include <cstddef>
#include <cstdarg>
#include <cstdint>
#include <type_traits>
#include <string>
#include <string_view>
#include <vector>
#include <list>
#include <unordered_map>
#include <map>
#include <functional>
#include <memory>
#include <tuple>
#include <utility>
#include <algorithm>
#include <cmath>
#include <initializer_list>
#include <span>
#include <bit>

// ---------------------------------------------------------------------------
// NVSE macros (must be defined before including NVSE headers)
// ---------------------------------------------------------------------------

// Disable static asserts -- they reference incomplete types during parsing
#define STATIC_ASSERT(a)
#define RUNTIME 1

// No-op assert macros
#define ASSERT(a) do { } while(0)
#define ASSERT_STR(a, b) do { } while(0)
#define ASSERT_CODE(a, b) do { } while(0)
#define ASSERT_STR_CODE(a, b, c) do { } while(0)

// Strip [[nodiscard]] -- older clang versions used by bindgen choke on it
#define nodiscard

// Minimal std::ranges namespace (xNVSE references it via namespace alias)
namespace std { namespace ranges {} }

// ---------------------------------------------------------------------------
// Windows API stubs
// ---------------------------------------------------------------------------
// These satisfy the declarations that xNVSE headers reference.
// Actual implementations come from the Windows SDK at link time.

typedef struct _RTL_CRITICAL_SECTION {
    void* DebugInfo;
    long LockCount;
    long RecursionCount;
    void* OwningThread;
    void* LockSemaphore;
    unsigned long SpinCount;
} CRITICAL_SECTION;

extern "C" {
    void EnterCriticalSection(CRITICAL_SECTION*);
    void LeaveCriticalSection(CRITICAL_SECTION*);

    typedef struct _iobuf FILE;

    void* malloc(unsigned int);  // size_t = unsigned int on i686
    void free(void*);

    unsigned long GetCurrentThreadId();
    void Sleep(unsigned long);
}

// Interlocked intrinsics -- declared (not defined) for bindgen parsing.
// At link time these resolve to compiler builtins or kernel32.
long InterlockedCompareExchange(long volatile* dest, long exchange, long comparand);
unsigned long InterlockedCompareExchange(unsigned long volatile* dest, unsigned long exchange, unsigned long comparand);

// Inline stubs -- bindgen only parses, never links, so bodies are fine.
inline long InterlockedIncrement(long volatile* p) { return ++(*p); }
inline long InterlockedDecrement(long volatile* p) { return --(*p); }
inline unsigned long InterlockedIncrement(unsigned long volatile* p) { return ++(*p); }
inline unsigned long InterlockedDecrement(unsigned long volatile* p) { return --(*p); }
inline unsigned int InterlockedIncrement(unsigned int volatile* p) { return ++(*p); }
inline unsigned int InterlockedDecrement(unsigned int volatile* p) { return --(*p); }

// Non-volatile overloads (xNVSE casts size_t* to these on i686)
inline long InterlockedIncrement(long* p) { return ++(*p); }
inline long InterlockedDecrement(long* p) { return --(*p); }
inline unsigned long InterlockedIncrement(unsigned long* p) { return ++(*p); }
inline unsigned long InterlockedDecrement(unsigned long* p) { return --(*p); }
inline unsigned int InterlockedIncrement(unsigned int* p) { return ++(*p); }
inline unsigned int InterlockedDecrement(unsigned int* p) { return --(*p); }

// ---------------------------------------------------------------------------
// Windows types
// ---------------------------------------------------------------------------
typedef unsigned long DWORD;
typedef unsigned char byte;

// ---------------------------------------------------------------------------
// Global min/max (some xNVSE code uses these without std:: prefix)
// ---------------------------------------------------------------------------
template<typename T>
inline const T& max(const T& a, const T& b) { return (a < b) ? b : a; }

template<typename T>
inline const T& min(const T& a, const T& b) { return (b < a) ? b : a; }

// Mixed signed/unsigned overloads -- xNVSE calls max(SInt32, UInt32) etc.
inline long max(long a, unsigned long b) { return (a < 0 || static_cast<unsigned long>(a) < b) ? static_cast<long>(b) : a; }
inline long max(unsigned long a, long b) { return (b < 0 || a > static_cast<unsigned long>(b)) ? static_cast<long>(a) : b; }
inline long min(long a, unsigned long b) { return (a < 0 || static_cast<unsigned long>(a) < b) ? a : static_cast<long>(b); }
inline long min(unsigned long a, long b) { return (b < 0 || a > static_cast<unsigned long>(b)) ? b : static_cast<long>(a); }

// ---------------------------------------------------------------------------
// Basic integer types (mirrors ITypes.h -- defined here so we don't
// depend on ITypes.h include order)
// ---------------------------------------------------------------------------
typedef unsigned char       UInt8;
typedef unsigned short      UInt16;
typedef unsigned long       UInt32;
typedef unsigned long long  UInt64;
typedef signed char         SInt8;
typedef signed short        SInt16;
typedef signed long         SInt32;
typedef signed long long    SInt64;
typedef float               Float32;
typedef double              Float64;

// ---------------------------------------------------------------------------
// Bitfield template (mirrors ITypes.h)
// ---------------------------------------------------------------------------
template <typename T>
class Bitfield {
public:
    Bitfield() : field(0) { }
    ~Bitfield() { }

    void Clear(void) { field = 0; }
    void RawSet(UInt32 data) { field = data; }

    void Set(UInt32 data) { field |= data; }
    void Clear(UInt32 data) { field &= ~data; }
    void UnSet(UInt32 data) { Clear(data); }
    void Mask(UInt32 data) { field &= data; }
    void Toggle(UInt32 data) { field ^= data; }
    void Write(UInt32 data, bool state) { if(state) Set(data); else Clear(data); }

    T Get(void) const { return field; }
    T Get(UInt32 data) const { return field & data; }
    T Extract(UInt32 bit) const { return (field >> bit) & 1; }
    T ExtractField(UInt32 shift, UInt32 length) { return (field >> shift) & (0xFFFFFFFF >> (32 - length)); }

    bool IsSet(UInt32 data) const { return ((field & data) == data) ? true : false; }
    bool IsUnSet(UInt32 data) const { return (field & data) ? false : true; }
    bool IsClear(UInt32 data) const { return IsUnSet(data); }

private:
    T field;
};

typedef Bitfield<UInt32> Bitfield32;
typedef Bitfield<UInt16> Bitfield16;
typedef Bitfield<UInt8>  Bitfield8;

// ---------------------------------------------------------------------------
// xNVSE headers
// ---------------------------------------------------------------------------
#include "nvse/containers.h"
#include "nvse/PluginAPI.h"
#include "nvse/GameAPI.h"
#include "nvse/Utilities.h"
