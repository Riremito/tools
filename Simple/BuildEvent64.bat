set PROJECTNAME=%1
set HEADERNAME=%PROJECTNAME:~,-2%
xcopy "..\%PROJECTNAME%\*.h" "..\Share\Simple\" /Y
xcopy "..\Release\%PROJECTNAME%.lib" "..\Share\Simple\" /Y