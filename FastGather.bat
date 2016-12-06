@echo off
:: Just put this in the same directory as your RapidTriage executable and run it to gather everything except the FileSystem
:: If you need hashes, just add an 'm' at the end of '-lnptu'

for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /format:list') do set datetime=%%I

%datetime% = set datetime=%datetime:~0,8%-%datetime:~8,6%

RapidTriage.exe -lnptu -o %datetime%_results.txt
