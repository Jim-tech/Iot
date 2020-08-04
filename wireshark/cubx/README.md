# Description
This wiretap plugin supports to read .cubx file with Wireshark.

# version
Wireshark 3.2.5

# path
wireshark-3.2.5\plugins\wiretap\cubx

# Commands Used:

- Env
  - cd C:\xxx\dev\wireshark
  - set WIRESHARK_BASE_DIR=C:\xxx\dev\wireshark
  - set WIRESHARK_LIB_DIR=C:\xxx\dev\wireshark\wireshark-win64-libs-3.2
  - set QT5_BASE_DIR=C:\Qt\5.15.0\msvc2019_64
  - rm -rf wsbuild64
  - mkdir wsbuild64
  - cd wsbuild64

- Build
  - cmake -G "Visual Studio 16 2019" -A x64 ..\wireshark-3.2.5
  - msbuild /m /p:Configuration=Release Wireshark.sln
  - msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
  - msbuild /m /p:Configuration=RelWithDebInfo plugins\wiretap\cubx\cubx.vcxproj

- Debug
  - set PATH="%PATH%;C:\xxx\dev\wireshark\wsbuild64\run\RelwithDebInfo"

# Copyright
leder.1983@163.com
