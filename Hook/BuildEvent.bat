set PROJECTNAME=%1
set HEADERNAME=%PROJECTNAME%
xcopy "..\%PROJECTNAME%64\*.h" "..\Share\Hook\" /Y
xcopy "..\Release\%PROJECTNAME%.lib" "..\Share\Hook\" /Y