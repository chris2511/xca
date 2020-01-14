

rem Compile
candle.exe -arch x64 -out xca.wixobj xca.wxs

rem Link: -sw1076: Silence warning LGHT1076
rem         ICE69: Mismatched component reference.

light.exe -b .. -sw1076 -ext WixUIExtension -ext WixUtilExtension xca.wixobj
