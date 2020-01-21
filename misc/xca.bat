

rem Compile
candle.exe -arch x64 -out xca.wixobj xca.wxs

rem Link: -sw1076: Silence warning LGHT1076
rem         ICE69: Mismatched component reference.

light.exe -b .. -sice:69 -sw1076 -ext WixUIExtension -ext WixUtilExtension xca.wixobj

rem  error LGHT0204 : ICE69 is OK

dir xca.msi

pause
