set PROJECTNAME=%1
set HEADERNAME=%PROJECTNAME:~,-2%
xcopy "..\%PROJECTNAME%\*.h" "..\Share\Hook\" /Y
xcopy "..\Release\%PROJECTNAME%.lib" "..\Share\Hook\" /Y