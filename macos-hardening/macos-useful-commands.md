# macOS Nuttige Opdragte

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

### MacOS Outomatiese Enumerasie Gereedskap

* **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
* **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum\_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum\_osx.rb)
* **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Spesifieke MacOS Opdragte
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
### Geïnstalleerde sagteware en dienste

Kyk vir **verdagte** toepassings wat geïnstalleer is en **voorregte** oor die geïnstalleerde hulpbronne:
```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Instaled framework
lsappinfo list #Installed Apps
launchtl list #Services
```
### Gebruikersprosesse

#### Lys alle prosesse
```
ps aux
```

#### Lys alle prosesse met meer inligting
```
ps auxww
```

#### Lys alle prosesse in 'n boomstruktuur
```
pstree
```

#### Lys alle prosesse wat deur 'n spesifieke gebruiker uitgevoer word
```
ps -u <gebruikersnaam>
```

#### Lys alle prosesse wat deur 'n spesifieke gebruiker uitgevoer word, met meer inligting
```
ps -u <gebruikersnaam> -ww
```

#### Lys alle prosesse wat deur 'n spesifieke gebruiker uitgevoer word, in 'n boomstruktuur
```
pstree -u <gebruikersnaam>
```

#### Lys alle prosesse wat deur 'n spesifieke gebruiker uitgevoer word, gegroepeer volgens gebruiker
```
ps -e -o user,pid,ppid,%cpu,%mem,args
```

#### Lys alle prosesse wat deur 'n spesifieke gebruiker uitgevoer word, gegroepeer volgens gebruiker, met meer inligting
```
ps -e -o user,pid,ppid,%cpu,%mem,args -ww
```

#### Lys alle prosesse wat deur 'n spesifieke gebruiker uitgevoer word, gegroepeer volgens gebruiker, in 'n boomstruktuur
```
pstree -U <gebruikersnaam>
```

#### Lys alle prosesse wat 'n spesifieke poort gebruik
```
lsof -i :<poort>
```

#### Lys alle prosesse wat 'n spesifieke lêer gebruik
```
lsof <lêernaam>
```

#### Lys alle prosesse wat 'n spesifieke TCP-verbinding gebruik
```
lsof -i tcp:<poort>
```

#### Lys alle prosesse wat 'n spesifieke UDP-verbinding gebruik
```
lsof -i udp:<poort>
```

#### Lys alle prosesse wat 'n spesifieke internetadres gebruik
```
lsof -i @<adres>
```

#### Lys alle prosesse wat 'n spesifieke internetadres en poort gebruik
```
lsof -i @<adres>:<poort>
```

#### Lys alle prosesse wat 'n spesifieke lêer gebruik, met meer inligting
```
lsof -V <lêernaam>
```

#### Lys alle prosesse wat 'n spesifieke TCP-verbinding gebruik, met meer inligting
```
lsof -i tcp:<poort> -V
```

#### Lys alle prosesse wat 'n spesifieke UDP-verbinding gebruik, met meer inligting
```
lsof -i udp:<poort> -V
```

#### Lys alle prosesse wat 'n spesifieke internetadres gebruik, met meer inligting
```
lsof -i @<adres> -V
```

#### Lys alle prosesse wat 'n spesifieke internetadres en poort gebruik, met meer inligting
```
lsof -i @<adres>:<poort> -V
```

#### Lys alle prosesse wat 'n spesifieke lêer gebruik, gegroepeer volgens proses-ID
```
lsof -t <lêernaam>
```

#### Lys alle prosesse wat 'n spesifieke TCP-verbinding gebruik, gegroepeer volgens proses-ID
```
lsof -i tcp:<poort> -t
```

#### Lys alle prosesse wat 'n spesifieke UDP-verbinding gebruik, gegroepeer volgens proses-ID
```
lsof -i udp:<poort> -t
```

#### Lys alle prosesse wat 'n spesifieke internetadres gebruik, gegroepeer volgens proses-ID
```
lsof -i @<adres> -t
```

#### Lys alle prosesse wat 'n spesifieke internetadres en poort gebruik, gegroepeer volgens proses-ID
```
lsof -i @<adres>:<poort> -t
```

#### Lys alle prosesse wat 'n spesifieke lêer gebruik, gegroepeer volgens proses-ID, met meer inligting
```
lsof -t -V <lêernaam>
```

#### Lys alle prosesse wat 'n spesifieke TCP-verbinding gebruik, gegroepeer volgens proses-ID, met meer inligting
```
lsof -i tcp:<poort> -t -V
```

#### Lys alle prosesse wat 'n spesifieke UDP-verbinding gebruik, gegroepeer volgens proses-ID, met meer inligting
```
lsof -i udp:<poort> -t -V
```

#### Lys alle prosesse wat 'n spesifieke internetadres gebruik, gegroepeer volgens proses-ID, met meer inligting
```
lsof -i @<adres> -t -V
```

#### Lys alle prosesse wat 'n spesifieke internetadres en poort gebruik, gegroepeer volgens proses-ID, met meer inligting
```
lsof -i @<adres>:<poort> -t -V
```

#### Lys alle prosesse wat 'n spesifieke lêer gebruik, gegroepeer volgens proses-ID, met meer inligting, sonder die proses se naam
```
lsof -t -V -F n <lêernaam>
```

#### Lys alle prosesse wat 'n spesifieke TCP-verbinding gebruik, gegroepeer volgens proses-ID, met meer inligting, sonder die proses se naam
```
lsof -i tcp:<poort> -t -V -F n
```

#### Lys alle prosesse wat 'n spesifieke UDP-verbinding gebruik, gegroepeer volgens proses-ID, met meer inligting, sonder die proses se naam
```
lsof -i udp:<poort> -t -V -F n
```

#### Lys alle prosesse wat 'n spesifieke internetadres gebruik, gegroepeer volgens proses-ID, met meer inligting, sonder die proses se naam
```
lsof -i @<adres> -t -V -F n
```

#### Lys alle prosesse wat 'n spesifieke internetadres en poort gebruik, gegroepeer volgens proses-ID, met meer inligting, sonder die proses se naam
```
lsof -i @<adres>:<poort> -t -V -F n
```
```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```
### Skep 'n gebruiker

Sonner vrae

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
