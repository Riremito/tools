set PROJECTNAME=%1
set HEADERNAME=%PROJECTNAME%
xcopy "..\%PROJECTNAME%64\*.h" "..\Share\Simple\" /Y
xcopy "..\Release\%PROJECTNAME%.lib" "..\Share\Simple\" /Y