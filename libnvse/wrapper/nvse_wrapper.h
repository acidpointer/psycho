// Wrapper header for xNVSE bindings
// This file is used by bindgen to generate Rust FFI bindings

// Include minimal C++ stdlib headers (stubs provided in OUT_DIR/include)
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

// NVSE macros that need to be defined before including NVSE headers
// For bindgen, we disable STATIC_ASSERT as it causes issues with incomplete types
#define STATIC_ASSERT(a)
#define RUNTIME 1

// ASSERT macro - for bindgen we just make it a no-op
#define ASSERT(a) do { } while(0)
#define ASSERT_STR(a, b) do { } while(0)
#define ASSERT_CODE(a, b) do { } while(0)
#define ASSERT_STR_CODE(a, b, c) do { } while(0)

// C++17 attributes compatibility - remove [[nodiscard]] entirely for bindgen
// We need to handle the entire [[...]] syntax, not just the keyword
#define nodiscard

// Minimal ranges namespace for C++20 compatibility
namespace std {
    namespace ranges {
        // Empty namespace - just needs to exist for namespace alias
    }
}

// Windows API stubs for types used by NVSE
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

    // FILE type from stdio
    typedef struct _iobuf FILE;

    // Memory functions
    void* malloc(unsigned long);
    void free(void*);

    // Windows API functions
    unsigned long GetCurrentThreadId();
    void Sleep(unsigned long);
}

// Interlocked functions - need to be outside extern "C" for overloading
long InterlockedCompareExchange(long volatile* dest, long exchange, long comparand);
unsigned long InterlockedCompareExchange(unsigned long volatile* dest, unsigned long exchange, unsigned long comparand);

// Interlocked functions - overloaded for different pointer types
inline long InterlockedIncrement(long volatile* p) { return ++(*p); }
inline long InterlockedDecrement(long volatile* p) { return --(*p); }
inline unsigned long InterlockedIncrement(unsigned long volatile* p) { return ++(*p); }
inline unsigned long InterlockedDecrement(unsigned long volatile* p) { return --(*p); }
inline unsigned int InterlockedIncrement(unsigned int volatile* p) { return ++(*p); }
inline unsigned int InterlockedDecrement(unsigned int volatile* p) { return --(*p); }

// Non-volatile overloads for reinterpret_cast usage (size_t* is unsigned int* on i686)
inline long InterlockedIncrement(long* p) { return ++(*p); }
inline long InterlockedDecrement(long* p) { return --(*p); }
inline unsigned long InterlockedIncrement(unsigned long* p) { return ++(*p); }
inline unsigned long InterlockedDecrement(unsigned long* p) { return --(*p); }
inline unsigned int InterlockedIncrement(unsigned int* p) { return ++(*p); }
inline unsigned int InterlockedDecrement(unsigned int* p) { return --(*p); }

// Windows types
typedef unsigned long DWORD;
typedef unsigned char byte;

// Global utility functions (some NVSE code uses these without std:: prefix)
// Template versions for same types
template<typename T>
inline const T& max(const T& a, const T& b) { return (a < b) ? b : a; }

template<typename T>
inline const T& min(const T& a, const T& b) { return (b < a) ? b : a; }

// Specific overloads for mixed signed/unsigned comparisons commonly used in NVSE
inline long max(long a, unsigned long b) { return (static_cast<unsigned long>(a) < b) ? static_cast<long>(b) : a; }
inline long max(unsigned long a, long b) { return (a < static_cast<unsigned long>(b)) ? b : static_cast<long>(a); }

// Define basic integer types from ITypes.h to avoid C++ stdlib dependencies
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

// Bitfield types from ITypes.h
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

// NVSE custom containers (include before PluginAPI)
#include "nvse/containers.h"

// Include main plugin API (path will be adjusted by build.rs with -I flags)
#include "nvse/PluginAPI.h"

// Include game API for runtime functions (ShowMessageBox, etc.)
#include "nvse/GameAPI.h"

// Include utilities (ShowErrorMessageBox, etc.)
#include "nvse/Utilities.h"
