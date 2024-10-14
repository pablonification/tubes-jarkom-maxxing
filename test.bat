@echo off

:: Path ke file client.py
set CLIENT_PATH="C:\Users\arqila_hmif\Documents\coding_itb\tubes_jarkom\client.py"

:: Menjalankan client dengan username arqila
start cmd /k "python %CLIENT_PATH% && echo 127.0.0.1 && echo 12345 && echo arqila && echo test_password && (for /l %%i in (0, 1, 4) do (echo Test message %%i && timeout /t 1)) && echo exit"

:: Menjalankan client dengan username sipayung
start cmd /k "python %CLIENT_PATH% && echo 127.0.0.1 && echo 12345 && echo sipayung && echo test_password && (for /l %%i in (0, 1, 4) do (echo Test message %%i && timeout /t 1)) && echo exit"

pause