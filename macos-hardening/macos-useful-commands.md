# Przydatne polecenia dla macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### Narzędzia automatycznego wyliczania dla MacOS

* **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
* **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum\_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum\_osx.rb)
* **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Konkretne polecenia dla MacOS
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
### Zainstalowane oprogramowanie i usługi

Sprawdź zainstalowane **podejrzane** aplikacje oraz **uprawnienia** dotyczące zainstalowanych zasobów:
```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Instaled framework
lsappinfo list #Installed Apps
launchtl list #Services
```
### Procesy użytkownika

User processes are the programs and applications that are executed by a user on a macOS system. These processes run in the user's context and have limited privileges compared to system processes.

Procesy użytkownika to programy i aplikacje uruchamiane przez użytkownika w systemie macOS. Te procesy działają w kontekście użytkownika i mają ograniczone uprawnienia w porównaniu do procesów systemowych.

#### Viewing User Processes

#### Wyświetlanie procesów użytkownika

To view the user processes running on a macOS system, you can use the `ps` command with the `-u` option followed by the username.

Aby wyświetlić procesy użytkownika działające w systemie macOS, można użyć polecenia `ps` z opcją `-u`, a następnie podać nazwę użytkownika.

```bash
ps -u username
```

#### Killing User Processes

#### Zabijanie procesów użytkownika

To terminate a user process, you can use the `kill` command followed by the process ID (PID) of the process.

Aby zakończyć proces użytkownika, można użyć polecenia `kill`, a następnie podać identyfikator procesu (PID) procesu.

```bash
kill PID
```

#### Monitoring User Processes

#### Monitorowanie procesów użytkownika

To monitor the resource usage of user processes in real-time, you can use the `top` command.

Aby monitorować w czasie rzeczywistym wykorzystanie zasobów przez procesy użytkownika, można użyć polecenia `top`.

```bash
top
```

#### Running User Processes with Elevated Privileges

#### Uruchamianie procesów użytkownika z podwyższonymi uprawnieniami

To run a user process with elevated privileges, you can use the `sudo` command followed by the command you want to execute.

Aby uruchomić proces użytkownika z podwyższonymi uprawnieniami, można użyć polecenia `sudo`, a następnie polecenia, które chcesz wykonać.

```bash
sudo command
```

#### Backgrounding User Processes

#### Przenoszenie procesów użytkownika do tła

To run a user process in the background, you can append an ampersand (`&`) at the end of the command.

Aby uruchomić proces użytkownika w tle, można dodać znak ampersand (`&`) na końcu polecenia.

```bash
command &
```

#### Foregrounding User Processes

#### Przenoszenie procesów użytkownika do pierwszego planu

To bring a backgrounded user process to the foreground, you can use the `fg` command followed by the job ID.

Aby przenieść proces użytkownika z tła do pierwszego planu, można użyć polecenia `fg`, a następnie podać identyfikator zadania.

```bash
fg job_id
```

#### Suspending User Processes

#### Wstrzymywanie procesów użytkownika

To suspend a running user process, you can use the `Ctrl + Z` keyboard shortcut.

Aby wstrzymać działanie uruchomionego procesu użytkownika, można użyć skrótu klawiszowego `Ctrl + Z`.

#### Resuming Suspended User Processes

#### Wznawianie wstrzymanych procesów użytkownika

To resume a suspended user process, you can use the `fg` command followed by the job ID.

Aby wznowić wstrzymany proces użytkownika, można użyć polecenia `fg`, a następnie podać identyfikator zadania.

```bash
fg job_id
```

#### Backgrounding Foregrounded User Processes

#### Przenoszenie procesów użytkownika z pierwszego planu do tła

To background a foregrounded user process, you can use the `Ctrl + Z` keyboard shortcut followed by the `bg` command.

Aby przenieść proces użytkownika z pierwszego planu do tła, można użyć skrótu klawiszowego `Ctrl + Z`, a następnie polecenia `bg`.

```bash
Ctrl + Z
bg
```

#### Listing Zombie Processes

#### Wyświetlanie procesów zombie

To list zombie processes on a macOS system, you can use the `ps` command with the `-axo` options and filter for processes with a status of `Z`.

Aby wyświetlić procesy zombie w systemie macOS, można użyć polecenia `ps` z opcjami `-axo` i filtrować procesy o statusie `Z`.

```bash
ps -axo pid,ppid,stat,command | grep -w Z
```
```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```
### Utwórz użytkownika

Bez podawania danych

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
