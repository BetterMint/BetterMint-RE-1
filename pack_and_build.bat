@echo off
echo Setting up Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)
if errorlevel 1 (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)
if errorlevel 1 (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)
if errorlevel 1 (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)

echo.
echo Compiling string packer...
cl /EHsc /O2 string_packer.cpp /Fe:string_packer.exe
if errorlevel 1 (
    echo Failed to compile string packer!
    echo Make sure you're running this from a Developer Command Prompt.
    pause
    exit /b 1
)

echo.
echo Packing strings in challenge.cpp...
string_packer.exe challenge.cpp challenge_packed.cpp
if errorlevel 1 (
    echo Failed to pack strings!
    pause
    exit /b 1
)

echo.
echo Compiling packed challenge...
cl /EHsc /O2 /GL /Ob2 /Oi /Ot /Oy challenge_packed.cpp /Fe:BetterMint_RE.exe /link /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF
if errorlevel 1 (
    echo Failed to compile packed challenge!
    pause
    exit /b 1
)

echo.
echo ========================================
echo SUCCESS! BetterMint_RE.exe created with obfuscated strings.
echo All strings are now packed and encrypted.
echo ========================================
pause
