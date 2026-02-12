@echo off
echo Building ssh-forwarder for Windows...

go build -o ssh-forwarder-windows-amd64.exe .

echo Build complete!
dir *.exe
