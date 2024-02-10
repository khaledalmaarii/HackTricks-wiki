# Comandi Utili per macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

### Strumenti di Enumerazione Automatica per macOS

* **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
* **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum\_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum\_osx.rb)
* **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Comandi Specifici per macOS
```bash
#System info
date
cal
uptime #show time from starting
w #list users
whoami #this user
finger username #info about user
uname -a #sysinfo
cat /proc/cpuinfo #processor
cat /proc/meminfo #memory
free #check memory
df #check disk

launchctl list #List services
atq #List "at" tasks for the user
sysctl -a #List kernel configuration
diskutil list #List connected hard drives
nettop #Monitor network usage of processes in top style

system_profiler SPSoftwareDataType #System info
system_profiler SPPrintersDataType #Printer
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Instaled framework
system_profiler SPDeveloperToolsDataType #Developer tools info
system_profiler SPStartupItemDataType #Startup Items
system_profiler SPNetworkDataType #Network Capabilities
system_profiler SPFirewallDataType #Firewall Status
system_profiler SPNetworkLocationDataType #Known Network
system_profiler SPBluetoothDataType #Bluetooth Info
system_profiler SPEthernetDataType #Ethernet Info
system_profiler SPUSBDataType #USB info
system_profiler SPAirPortDataType #Airport Info


#Searches
mdfind password #Show all the files that contains the word password
mfind -name password #List all the files containing the word password in the name


#Open any app
open -a <Application Name> --hide #Open app hidden
open some.doc -a TextEdit #Open a file in one application


#Computer doesn't go to sleep
caffeinate &


#Screenshot
# This will ask for permission to the user
screencapture -x /tmp/ss.jpg #Save screenshot in that file


#Get clipboard info
pbpaste


#system_profiler
system_profiler --help #This command without arguments take lot of memory and time.
system_profiler -listDataTypes
system_profiler SPSoftwareDataType SPNetworkDataType


#Network
arp -i en0 -l -a #Print the macOS device's ARP table
lsof -i -P -n | grep LISTEN
smbutil statshares -a #View smb shares mounted to the hard drive

#networksetup - set or view network options: Proxies, FW options and more
networksetup -listallnetworkservices #List network services
networksetup -listallhardwareports #Hardware ports
networksetup -getinfo Wi-Fi #Wi-Fi info
networksetup -getautoproxyurl Wi-Fi #Get proxy URL for Wifi
networksetup -getwebproxy Wi-Fi #Wifi Web proxy
networksetup -getftpproxy Wi-Fi #Wifi ftp proxy


#Brew
brew list #List installed
brew search <text> #Search package
brew info <formula>
brew install <formula>
brew uninstall <formula>
brew cleanup #Remove older versions of installed formulae.
brew cleanup <formula> #Remove older versions of specified formula.


#Make the machine talk
say hello -v diego
#spanish: diego, Jorge, Monica
#mexican: Juan, Paulina
#french: Thomas, Amelie

########### High privileges actions
sudo purge #purge RAM
#Sharing preferences
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist (enable ssh)
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist (disable ssh)
#Start apache
sudo apachectl (start|status|restart|stop)
##Web folder: /Library/WebServer/Documents/
#Remove DNS cache
dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```
### Software e Servizi Installati

Controlla le applicazioni installate **sospette** e i **privilegi** sulle risorse installate:
```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Instaled framework
lsappinfo list #Installed Apps
launchtl list #Services
```
### Processi Utente

#### List all running processes

#### Elencare tutti i processi in esecuzione

```bash
ps aux
```

#### List all processes with more information

#### Elencare tutti i processi con ulteriori informazioni

```bash
ps auxww
```

#### List all processes in a tree-like structure

#### Elencare tutti i processi in una struttura ad albero

```bash
pstree
```

#### List all processes with their associated threads

#### Elencare tutti i processi con i relativi thread associati

```bash
ps -eLf
```

#### List all processes with their open files

#### Elencare tutti i processi con i relativi file aperti

```bash
lsof -n -P
```

#### List all processes with their network connections

#### Elencare tutti i processi con le relative connessioni di rete

```bash
lsof -i
```

#### List all processes with their listening network ports

#### Elencare tutti i processi con le relative porte di rete in ascolto

```bash
lsof -i -P | grep LISTEN
```

#### List all processes with their associated shared libraries

#### Elencare tutti i processi con le relative librerie condivise associate

```bash
lsof -n -P | grep '\.so'
```

#### List all processes with their environment variables

#### Elencare tutti i processi con le relative variabili d'ambiente

```bash
ps eww
```

#### List all processes with their command line arguments

#### Elencare tutti i processi con i relativi argomenti della riga di comando

```bash
ps auxww | awk '{print $11}'
```

#### List all processes with their parent process ID (PPID)

#### Elencare tutti i processi con il relativo ID del processo padre (PPID)

```bash
ps -eo pid,ppid,comm
```

#### List all processes with their process ID (PID) and parent process ID (PPID)

#### Elencare tutti i processi con il relativo ID del processo (PID) e ID del processo padre (PPID)

```bash
ps -eo pid,ppid,comm
```

#### List all processes with their process ID (PID), parent process ID (PPID), and command name

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e nome del comando

```bash
ps -eo pid,ppid,comm
```

#### List all processes with their process ID (PID), parent process ID (PPID), and command line arguments

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e argomenti della riga di comando

```bash
ps -eo pid,ppid,args
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente

```bash
ps -eo pid,ppid,user
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo

```bash
ps -eo pid,ppid,user
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by user

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per utente

```bash
ps -eo pid,ppid,user | sort -k3
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process ID

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per ID del processo

```bash
ps -eo pid,ppid,user | sort -k1
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by parent process ID

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per ID del processo padre

```bash
ps -eo pid,ppid,user | sort -k2
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by command name

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per nome del comando

```bash
ps -eo pid,ppid,user,comm | sort -k4
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process start time

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'ora di avvio del processo

```bash
ps -eo pid,ppid,user,lstart | sort -k5
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process CPU usage

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della CPU del processo

```bash
ps -eo pid,ppid,user,%cpu | sort -k4 -nr
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process memory usage

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della memoria del processo

```bash
ps -eo pid,ppid,user,%mem | sort -k4 -nr
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process virtual memory usage

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della memoria virtuale del processo

```bash
ps -eo pid,ppid,user,vsize | sort -k4 -nr
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process resident set size (RSS)

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per la dimensione del set di residenti del processo (RSS)

```bash
ps -eo pid,ppid,user,rss | sort -k4 -nr
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process file size

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per la dimensione del file del processo

```bash
ps -eo pid,ppid,user,fsize | sort -k4 -nr
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process start time in reverse order

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'ora di avvio del processo in ordine inverso

```bash
ps -eo pid,ppid,user,lstart | sort -k5 -r
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process CPU usage in reverse order

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della CPU del processo in ordine inverso

```bash
ps -eo pid,ppid,user,%cpu | sort -k4 -n
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process memory usage in reverse order

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della memoria del processo in ordine inverso

```bash
ps -eo pid,ppid,user,%mem | sort -k4 -n
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process virtual memory usage in reverse order

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della memoria virtuale del processo in ordine inverso

```bash
ps -eo pid,ppid,user,vsize | sort -k4 -n
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process resident set size (RSS) in reverse order

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per la dimensione del set di residenti del processo (RSS) in ordine inverso

```bash
ps -eo pid,ppid,user,rss | sort -k4 -n
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process file size in reverse order

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per la dimensione del file del processo in ordine inverso

```bash
ps -eo pid,ppid,user,fsize | sort -k4 -n
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process CPU usage and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della CPU del processo e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,%cpu | sort -k4 -nr | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process memory usage and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della memoria del processo e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,%mem | sort -k4 -nr | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process virtual memory usage and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della memoria virtuale del processo e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,vsize | sort -k4 -nr | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process resident set size (RSS) and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per la dimensione del set di residenti del processo (RSS) e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,rss | sort -k4 -nr | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process file size and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per la dimensione del file del processo e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,fsize | sort -k4 -nr | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process start time and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'ora di avvio del processo e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,lstart | sort -k5 | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process CPU usage in reverse order and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della CPU del processo in ordine inverso e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,%cpu | sort -k4 -n | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process memory usage in reverse order and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della memoria del processo in ordine inverso e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,%mem | sort -k4 -n | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process virtual memory usage in reverse order and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per l'utilizzo della memoria virtuale del processo in ordine inverso e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,vsize | sort -k4 -n | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process resident set size (RSS) in reverse order and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per la dimensione del set di residenti del processo (RSS) in ordine inverso e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,rss | sort -k4 -n | head -n 10
```

#### List all processes with their process ID (PID), parent process ID (PPID), and user running the process, sorted by process file size in reverse order and display the top 10 processes

#### Elencare tutti i processi con il relativo ID del processo (PID), ID del processo padre (PPID) e utente che esegue il processo, ordinati per la dimensione del file del processo in ordine inverso e visualizzare i primi 10 processi

```bash
ps -eo pid,ppid,user,fsize | sort -k4 -n | head -n 10
```
```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```
### Creare un utente

Senza prompt

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
