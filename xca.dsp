# Microsoft Developer Studio Project File - Name="xca" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=xca - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "xca.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "xca.mak" CFG="xca - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "xca - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "xca - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "xca - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir ""
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir ""
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD CPP /nologo /MD /W3 /GX /O1 /I "$(QTDIR)\include" /I "_$(QTDIR)\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "QT_DLL" /D "QT_NO_DEBUG" /D "QT_THREAD_SUPPORT" /D "$(QTDIR)\mkspecs\win32-msvc" /FD /D /I -Zm200 /c
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x407
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /machine:IX86
# ADD LINK32 $(QTDIR)\lib\qt-mt230nc.lib $(QTDIR)\lib\qtmain.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib imm32.lib winmm.lib wsock32.lib winspool.lib delayimp.lib SSLeay32.lib libeay32.lib libdb41.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib imm32.lib wsock32.lib winspool.lib winmm.lib /nologo /subsystem:windows /machine:IX86 /DELAYLOAD:comdlg32.dll /DELAYLOAD:oleaut32.dll /DELAYLOAD:winmm.dll /DELAYLOAD:wsock32.dll /DELAYLOAD:winspool.dll

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "$(QTDIR)\include" /I "$(QTDIR)\mkspecs\win32-msvc" /I "_$(QTDIR)\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "QT_DLL" /D "QT_THREAD_SUPPORT" /FD /D /GZ -Zm200 /c
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x407
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /machine:IX86
# ADD LINK32 $(QTDIR)\lib\qt-mt230nc.lib $(QTDIR)\lib\qtmain.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib imm32.lib winmm.lib wsock32.lib winspool.lib SSLeay32.lib libeay32.lib libdb41.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib imm32.lib wsock32.lib winspool.lib winmm.lib $(QTDIR)\lib\qt.lib $(QTDIR)\lib\qtmain.lib /nologo /subsystem:windows /incremental:no /debug /machine:IX86 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "xca - Win32 Release"
# Name "xca - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\lib\asn1int.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\asn1time.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\CertDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I ".."

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\CertView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\clicklabel.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\CrlDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\CrlView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\db_base.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_crl.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\db_key.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\db_temp.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\db_x509.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\db_x509req.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_x509super.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\distname.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ExportCert.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ExportKey.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ExportTinyCA.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\func.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ImportMulti.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\KeyDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\KeyView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\load_obj.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\main.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\MainWindow.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\NewX509.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\NewX509_ext.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\oid.cpp
# End Source File
# Begin Source File

SOURCE=.\lib\pass_info.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\pki_base.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_crl.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\pki_key.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\pki_pkcs12.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_pkcs7.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\pki_temp.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\pki_x509.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\pki_x509req.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_x509super.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ReqDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\ReqView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\TempView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\validity.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\x509name.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\x509rev.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\x509v3ext.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\XcaListView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\lib\asn1int.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\asn1int.h
InputName=asn1int

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\asn1int.h
InputName=asn1int

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\asn1time.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\asn1time.h
InputName=asn1time

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\asn1time.h
InputName=asn1time

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\base.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\base.h
InputName=base

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\base.h
InputName=base

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\CertDetail.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\CertDetail.h
InputName=CertDetail

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\CertDetail.h
InputName=CertDetail

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\CertView.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\view
InputPath=.\view\CertView.h
InputName=CertView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\view
InputPath=.\view\CertView.h
InputName=CertView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\clicklabel.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\clicklabel.h
InputName=clicklabel

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\clicklabel.h
InputName=clicklabel

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\CrlDetail.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\CrlDetail.h
InputName=CrlDetail

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\CrlDetail.h
InputName=CrlDetail

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\CrlView.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\view
InputPath=.\view\CrlView.h
InputName=CrlView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\view
InputPath=.\view\CrlView.h
InputName=CrlView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_base.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\db_base.h
InputName=db_base

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\db_base.h
InputName=db_base

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_crl.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\db_crl.h
InputName=db_crl

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\db_crl.h
InputName=db_crl

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_key.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\db_key.h
InputName=db_key

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\db_key.h
InputName=db_key

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_temp.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\db_temp.h
InputName=db_temp

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\db_temp.h
InputName=db_temp

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_x509.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\db_x509.h
InputName=db_x509

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\db_x509.h
InputName=db_x509

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_x509req.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\db_x509req.h
InputName=db_x509req

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\db_x509req.h
InputName=db_x509req

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\db_x509super.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\db_x509super.h
InputName=db_x509super

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\db_x509super.h
InputName=db_x509super

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\distname.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\distname.h
InputName=distname

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\distname.h
InputName=distname

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\exception.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\exception.h
InputName=exception

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\exception.h
InputName=exception

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ExportCert.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\ExportCert.h
InputName=ExportCert

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\ExportCert.h
InputName=ExportCert

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ExportKey.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\ExportKey.h
InputName=ExportKey

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\ExportKey.h
InputName=ExportKey

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ExportTinyCA.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\ExportTinyCA.h
InputName=ExportTinyCA

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\ExportTinyCA.h
InputName=ExportTinyCA

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\func.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\func.h
InputName=func

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\func.h
InputName=func

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ImportMulti.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\ImportMulti.h
InputName=ImportMulti

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\KeyDetail.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\KeyDetail.h
InputName=KeyDetail

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\KeyView.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\view
InputPath=.\view\KeyView.h
InputName=KeyView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\view
InputPath=.\view\KeyView.h
InputName=KeyView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\load_obj.h
# End Source File
# Begin Source File

SOURCE=.\widgets\MainWindow.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\MainWindow.h
InputName=MainWindow

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\MainWindow.h
InputName=MainWindow

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\NewX509.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\NewX509.h
InputName=NewX509

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\NewX509.h
InputName=NewX509

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pass_info.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pass_info.h
InputName=pass_info

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pass_info.h
InputName=pass_info

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_base.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_base.h
InputName=pki_base

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_base.h
InputName=pki_base

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_crl.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_crl.h
InputName=pki_crl

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_crl.h
InputName=pki_crl

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_key.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_key.h
InputName=pki_key

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_key.h
InputName=pki_key

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_pkcs12.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_pkcs12.h
InputName=pki_pkcs12

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_pkcs12.h
InputName=pki_pkcs12

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_pkcs7.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_pkcs7.h
InputName=pki_pkcs7

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_pkcs7.h
InputName=pki_pkcs7

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_temp.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_temp.h
InputName=pki_temp

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_temp.h
InputName=pki_temp

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_x509.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_x509.h
InputName=pki_x509

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_x509.h
InputName=pki_x509

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_x509req.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_x509req.h
InputName=pki_x509req

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_x509req.h
InputName=pki_x509req

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\pki_x509super.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\pki_x509super.h
InputName=pki_x509super

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\pki_x509super.h
InputName=pki_x509super

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\ReqDetail.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\ReqDetail.h
InputName=ReqDetail

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\ReqDetail.h
InputName=ReqDetail

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\ReqView.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\view
InputPath=.\view\ReqView.h
InputName=ReqView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\view
InputPath=.\view\ReqView.h
InputName=ReqView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\TempView.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\view
InputPath=.\view\TempView.h
InputName=TempView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\view
InputPath=.\view\TempView.h
InputName=TempView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\validity.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\widgets
InputPath=.\widgets\validity.h
InputName=validity

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\widgets
InputPath=.\widgets\validity.h
InputName=validity

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\x509name.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\x509name.h
InputName=x509name

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\x509name.h
InputName=x509name

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\x509rev.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\x509rev.h
InputName=x509rev

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\x509rev.h
InputName=x509rev

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\x509v3ext.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\lib
InputPath=.\lib\x509v3ext.h
InputName=x509v3ext

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\lib
InputPath=.\lib\x509v3ext.h
InputName=x509v3ext

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\XcaListView.h

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - MOC ing $(InputPath)
InputDir=.\view
InputPath=.\view\XcaListView.h
InputName=XcaListView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - Moc ing $(InputName)
InputDir=.\view
InputPath=.\view\XcaListView.h
InputName=XcaListView

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\img\key.ico
# End Source File
# Begin Source File

SOURCE=.\misc\xca.rc
# End Source File
# End Group
# Begin Group "Forms"

# PROP Default_Filter "ui"
# Begin Source File

SOURCE=.\ui\CertDetail.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\CertDetail.ui
InputName=CertDetail

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\CertDetail.ui
InputName=CertDetail

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\CertExtend.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\CertExtend.ui
InputName=CertExtend

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\CertExtend.ui
InputName=CertExtend

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\CrlDetail.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\CrlDetail.ui
InputName=CrlDetail

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\CrlDetail.ui
InputName=CrlDetail

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ExportCert.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ExportCert.ui
InputName=ExportCert

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ExportCert.ui
InputName=ExportCert

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ExportKey.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ExportKey.ui
InputName=ExportKey

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ExportKey.ui
InputName=ExportKey

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ExportTinyCA.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ExportTinyCA.ui
InputName=ExportTinyCA

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ExportTinyCA.ui
InputName=ExportTinyCA

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ImportMulti.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ImportMulti.ui
InputName=ImportMulti

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\KeyDetail.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\KeyDetail.ui
InputName=KeyDetail

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\KeyDetail.ui
InputName=KeyDetail

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\MainWindow.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\MainWindow.ui
InputName=MainWindow

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\MainWindow.ui
InputName=MainWindow

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\NewKey.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\NewKey.ui
InputName=NewKey

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\NewKey.ui
InputName=NewKey

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\NewX509.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\NewX509.ui
InputName=NewX509

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\NewX509.ui
InputName=NewX509

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\PassRead.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\PassRead.ui
InputName=PassRead

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\PassRead.ui
InputName=PassRead

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\PassWrite.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\PassWrite.ui
InputName=PassWrite

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\PassWrite.ui
InputName=PassWrite

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ReqDetail.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ReqDetail.ui
InputName=ReqDetail

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\ReqDetail.ui
InputName=ReqDetail

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\TrustState.ui

!IF  "$(CFG)" == "xca - Win32 Release"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\TrustState.ui
InputName=TrustState

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\ui_$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\ui_moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\ui_moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# Begin Custom Build - UI compiling $(InputName)
InputDir=.\ui
InputPath=.\ui\TrustState.ui
InputName=TrustState

BuildCmds= \
	%qtdir%\bin\uic.exe $(InputPath) -o $(InputDir)\$(InputName).h \
	%qtdir%\bin\uic.exe $(InputPath) -i $(InputName).h -o $(InputDir)\$(InputName).cpp \
	%qtdir%\bin\moc.exe $(InputDir)\$(InputName).h -o $(InputDir)\moc_$(InputName).cpp \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\moc_$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Translations"

# PROP Default_Filter "ts"
# Begin Source File

SOURCE=.\lang\xca_de.ts
# End Source File
# Begin Source File

SOURCE=.\lang\xca_es.ts
# End Source File
# End Group
# Begin Group "Generated"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\lib\moc_asn1int.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_asn1time.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_base.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_CertDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\moc_CertView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_clicklabel.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_CrlDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\moc_CrlView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_db_base.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_db_crl.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_db_key.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_db_temp.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_db_x509.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_db_x509req.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_db_x509super.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_distname.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_exception.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_ExportCert.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_ExportKey.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_ExportTinyCA.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_func.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_ImportMulti.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "."

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_KeyDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\moc_KeyView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_MainWindow.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_NewX509.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pass_info.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_base.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_crl.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_key.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_pkcs12.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_pkcs7.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_temp.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_x509.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_x509req.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_pki_x509super.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_ReqDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\moc_ReqView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\moc_TempView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\widgets\moc_validity.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_x509name.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_x509rev.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\lib\moc_x509v3ext.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# ADD CPP /I "..\\"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\view\moc_XcaListView.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_CertDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_CertExtend.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_CrlDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_ExportCert.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_ExportKey.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_ExportTinyCA.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_ImportMulti.cpp
# End Source File
# Begin Source File

SOURCE=.\ui\ui_KeyDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_MainWindow.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets" /I ".\view"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_CertDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_CertExtend.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_CrlDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_ExportCert.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_ExportKey.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_ExportTinyCA.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_ImportMulti.cpp
# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_KeyDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_MainWindow.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_NewKey.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_NewX509.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_PassRead.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_PassWrite.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_ReqDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_moc_TrustState.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_NewKey.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_NewX509.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_PassRead.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_PassWrite.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_ReqDetail.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ui\ui_TrustState.cpp

!IF  "$(CFG)" == "xca - Win32 Release"

# ADD CPP /I "." /I ".\widgets"

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
