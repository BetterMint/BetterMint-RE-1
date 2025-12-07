# Building the Obfuscated Challenge

## Quick Start

### Option 1: Use the Batch Script (Recommended)

1. Open **x64 Native Tools Command Prompt for VS** from:
   ```
   C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2026\Visual Studio Tools\VC\x64 Native Tools Command Prompt for VS
   ```

2. Navigate to the project directory:
   ```cmd
   cd "C:\Users\Administrator\Downloads\RE Challenge"
   ```

3. Run the build script:
   ```cmd
   pack_and_build.bat
   ```

This will:
- Compile the string packer
- Pack and obfuscate all strings in challenge.cpp
- Compile the final obfuscated binary

### Option 2: Manual Build

1. Open **x64 Native Tools Command Prompt for VS**

2. Navigate to the project directory

3. Compile the string packer:
   ```cmd
   cl /EHsc /O2 string_packer.cpp /Fe:string_packer.exe
   ```

4. Pack the strings:
   ```cmd
   string_packer.exe challenge.cpp challenge_packed.cpp
   ```

5. Compile the obfuscated challenge:
   ```cmd
   cl /EHsc /O2 /GL /Ob2 /Oi /Ot /Oy challenge_packed.cpp /Fe:BetterMint_RE.exe /link /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF
   ```

## What Gets Obfuscated

The string packer will:
- ✅ Find all string literals in challenge.cpp
- ✅ Encrypt them with XOR + index-based encryption
- ✅ Replace them with `d1_unpack()` calls
- ✅ Generate random variable names (STR_xxxxx)
- ✅ Automatically add `.c_str()` for C string functions
- ✅ Skip strings in #pragma directives

## Result

After building, `BetterMint_RE.exe` will have:
- All strings obfuscated as byte arrays
- Strings not visible in plain text searches
- Random variable names for packed strings
- Full anti-debug and anti-VM protections

## Testing

To test the obfuscated version:
```cmd
BetterMint_RE.exe
```

The output should be readable (strings are unpacked at runtime), but the strings won't be visible in the binary when analyzed with tools like `strings.exe` or hex editors.

