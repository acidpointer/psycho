// #include <cstdint>
// #include <cstdio>
// #include <string>
// #include <vector>
// #include <unordered_map>
// #include <memory>
// #include <chrono>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
// #include <stddef.h>

#include "platform.h"

// #include <ranges>
// #include <algorithm>




#include "common/IErrors.h"
#include "common/ITypes.h"
#include "f4se/GameTypes.h"

// #ifndef _WIN32
//     // If we not on Windows include wrapper for min/max
//     #include "minmax.h"
// #endif // _WIN32


// #include "f4se/GameTypes.h"


// Our fix for minmax will not work with C++20 ranges
// Let's do some tricky magic workaround
// #ifndef _WIN32
//     #ifndef MINMAX_FIX
//         #pragma push_macro("min")
//         #undef min
//         #pragma push_macro("max")
//         #undef max

//         #define MINMAX_FIX
//     #endif // MINMAX_FIX


//     #include <ranges>
//     #include <algorithm>


//     #ifdef MINMAX_FIX
//         #pragma pop_macro("min")
//         #pragma pop_macro("max")
//         #undef MINMAX_FIX
//     #endif // MINMAX_FIX
// #endif // _WIN32

// #include "f4se_common/Utilities.h"
// #include "f4se_common/SafeWrite.h"

// #include "f4se/NiTypes.h"
// #include "f4se/ObScript.h"
// #include "f4se/GameWorkshop.h"
#include "f4se/PluginAPI.h"
// #include "f4se/PluginManager.h"
#include "f4se/GameAPI.h"
// #include "f4se/GameSettings.h"
// #include "f4se/InputMap.h"


// #include "f4se/GameTypes.h"
