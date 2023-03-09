# ICMP-Shellcode-Loader
A Golang shellcode loader that receives payloads via ICMP packets to bypass firewalls.
The shellcode loader is developed for Windows and the C2 software for Linux systems.

## Requirements
- Windows OS
- Linux OS or download pre-compiled icmp-c2-server
- GoLand IDE
- Metasploit (to generate shellcodes)
- VPS (only for C&C over internet)

## How to build
- insert the IP of your VPS in the icmp-sc-loader.go 
- build icmp-sc-loader.go on Windows
- build icmp-c2-server.go static on Linux (build with CGO_ENABLED=0 and -ldflags '-extldflags "-static"') or download pre-compiled icmp-c2-server

<img src="https://user-images.githubusercontent.com/79810730/223784387-a94cffea-f29d-4463-97ef-067c42e40b95.PNG" alt="static compile" style="width:50%;"/>

## How to use
- generate custom shellcode with msfvenom (it is important that the exitfunc is set to thread) i.e. ```msfvenom -p windows/x64/exec CMD=calc EXITFUNC=thread -f hex```
 
- start the C2 software as root on your Linux system or your Linux VPS i.e. with ```./icmp-c2-server -a 64 -os win -sc <your shellcode>```
- start the shellcode loader on your Windows and enjoy

![example](https://user-images.githubusercontent.com/79810730/223886417-9b944229-acb9-4a97-8107-2895e22adac5.gif)
