# Unstrip: Ghidra plugin to rename functions in stripped binaries

## Conditions
1. Binary has to use a debug function, such as ```assert(value, function_name, error_message```
2. Calling convention to said function has to be cdecl, the function name parameter will be searched in ```ESP + $offset```
