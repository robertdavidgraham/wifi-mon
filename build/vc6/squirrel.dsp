# Microsoft Developer Studio Project File - Name="squirrel" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=squirrel - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "squirrel.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "squirrel.mak" CFG="squirrel - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "squirrel - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "squirrel - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""$/Squirrel", IGAAAAAA"
# PROP Scc_LocalPath "."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "squirrel - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /Zi /O2 /I "../Ferret/src/module" /I "../Ferret/src/include" /I "../Ferret/src" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /FR /YX /FD /c
# ADD BASE RSC /l 0x1009 /d "NDEBUG"
# ADD RSC /l 0x1009 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib setargv.obj /nologo /subsystem:console /profile /debug /machine:I386

!ELSEIF  "$(CFG)" == "squirrel - Win32 Debug"

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
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "src/module" /I "src/sqdb" /I "src" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fr /YX /FD /GZ /c
# ADD BASE RSC /l 0x1009 /d "_DEBUG"
# ADD RSC /l 0x1009 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib setargv.obj /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "squirrel - Win32 Release"
# Name "squirrel - Win32 Debug"
# Begin Group "display"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\display\dadapters.c

!IF  "$(CFG)" == "squirrel - Win32 Release"

!ELSEIF  "$(CFG)" == "squirrel - Win32 Debug"

# SUBTRACT CPP /I "src"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\display\dbeacon.c

!IF  "$(CFG)" == "squirrel - Win32 Release"

!ELSEIF  "$(CFG)" == "squirrel - Win32 Debug"

# SUBTRACT CPP /I "src"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\display\dbssid.c

!IF  "$(CFG)" == "squirrel - Win32 Release"

!ELSEIF  "$(CFG)" == "squirrel - Win32 Debug"

# SUBTRACT CPP /I "src"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\display\dbssidlist.c

!IF  "$(CFG)" == "squirrel - Win32 Release"

!ELSEIF  "$(CFG)" == "squirrel - Win32 Debug"

# SUBTRACT CPP /I "src"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\display\deventlist.c
# End Source File
# Begin Source File

SOURCE=.\src\display\deventpkt.c
# End Source File
# Begin Source File

SOURCE=.\src\display\display.c
# End Source File
# Begin Source File

SOURCE=.\src\display\dprobes.c

!IF  "$(CFG)" == "squirrel - Win32 Release"

!ELSEIF  "$(CFG)" == "squirrel - Win32 Debug"

# SUBTRACT CPP /I "src"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\display\dstation.c
# End Source File
# Begin Source File

SOURCE=.\src\display\dxmit.c
# End Source File
# End Group
# Begin Group "sqdb"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\sqdb\sqdb.c
# End Source File
# Begin Source File

SOURCE=.\src\sqdb\sqdb.h
# End Source File
# Begin Source File

SOURCE=.\src\sqdb\sqdb2.h
# End Source File
# End Group
# Begin Group "netstack"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\netstack\stackarp.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackdhcp.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackdns.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackdnsmulti.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackdnsnetbios.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackdnssrv.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackether.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackip.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stacktcp.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackudp.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackwep.c
# End Source File
# Begin Source File

SOURCE=.\src\netstack\stackwifi.c
# End Source File
# End Group
# Begin Group "module"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\module\hexval.c
# End Source File
# Begin Source File

SOURCE=.\src\module\manuf.c
# End Source File
# Begin Source File

SOURCE=.\src\module\mongoose.c
# End Source File
# Begin Source File

SOURCE=.\src\module\mongoose.h
# End Source File
# Begin Source File

SOURCE=.\src\module\mystring.c
# End Source File
# Begin Source File

SOURCE=.\src\module\pcapfile.c
# End Source File
# Begin Source File

SOURCE=.\src\module\pcaplive.c
# End Source File
# Begin Source File

SOURCE=.\src\module\pixie.c
# End Source File
# End Group
# Begin Source File

SOURCE=.\src\squirrel.c
# End Source File
# End Target
# End Project
