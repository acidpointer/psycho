#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <dinput8.dll>" >&2
    exit 2
fi

DLL="$1"
OBJDUMP="${OBJDUMP:-i686-w64-mingw32-objdump}"

if [[ ! -f "$DLL" ]]; then
    echo "Missing DLL: $DLL" >&2
    exit 1
fi

DETAILS="$($OBJDUMP -p "$DLL")"

if ! grep -q 'file format pei-i386' <<<"$DETAILS"; then
    echo "Syringe is not a 32-bit PE DLL: $DLL" >&2
    exit 1
fi

mapfile -t exports < <(
    awk '
        /\[Ordinal\/Name Pointer\] Table/ { in_exports = 1; next }
        in_exports && /^PE File/ { exit }
        in_exports && seen_export && /^[[:space:]]*$/ { exit }
        in_exports && /^[[:space:]]*\[[[:space:]]*[0-9]+\]/ {
            print $NF
            seen_export = 1
        }
    ' <<<"$DETAILS"
)
expected_exports=(
    DirectInput8Create
    DllCanUnloadNow
    DllGetClassObject
    DllRegisterServer
    DllUnregisterServer
)

if [[ ${#exports[@]} -ne ${#expected_exports[@]} ]]; then
    echo "Unexpected Syringe export count: ${#exports[@]}" >&2
    printf 'Actual exports: %s\n' "${exports[*]}" >&2
    exit 1
fi

for index in "${!expected_exports[@]}"; do
    if [[ "${exports[$index]}" != "${expected_exports[$index]}" ]]; then
        echo "Unexpected Syringe export at ordinal $((index + 1)): ${exports[$index]}" >&2
        exit 1
    fi
done

mapfile -t imports < <(awk '/DLL Name:/ { print $3 }' <<<"$DETAILS")
msvcrt_imports="KERNEL32.dll msvcrt.dll"
ucrt_imports="KERNEL32.dll api-ms-win-crt-convert-l1-1-0.dll api-ms-win-crt-heap-l1-1-0.dll api-ms-win-crt-private-l1-1-0.dll api-ms-win-crt-runtime-l1-1-0.dll api-ms-win-crt-stdio-l1-1-0.dll api-ms-win-crt-string-l1-1-0.dll"
if [[ "${imports[*]}" != "$msvcrt_imports" && "${imports[*]}" != "$ucrt_imports" ]]; then
    echo "Unexpected Syringe imports: ${imports[*]}" >&2
    exit 1
fi
