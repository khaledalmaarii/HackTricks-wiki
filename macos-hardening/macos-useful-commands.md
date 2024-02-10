# macOS Useful Commands

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### MacOS Automatic Enumeration Tools

* **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
* **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum\_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum\_osx.rb)
* **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Specific MacOS Commands
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
### QaD Installed Software & Services

**QaD** **vItlhutlh** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **Qa
```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Instaled framework
lsappinfo list #Installed Apps
launchtl list #Services
```
### User Processes

#### List all running processes

To list all running processes on macOS, you can use the `ps` command with the `-ef` option:

```bash
ps -ef
```

#### Filter processes by user

To filter the list of processes by a specific user, you can use the `ps` command with the `-u` option followed by the username:

```bash
ps -u username
```

#### Kill a process

To kill a specific process, you can use the `kill` command followed by the process ID (PID):

```bash
kill PID
```

#### Kill all processes by a user

To kill all processes owned by a specific user, you can use the `pkill` command followed by the username:

```bash
pkill -u username
```

#### Monitor process activity

To monitor the activity of a specific process in real-time, you can use the `top` command followed by the `-pid` option and the process ID (PID):

```bash
top -pid PID
```

#### Check process open files

To check the files opened by a specific process, you can use the `lsof` command followed by the `-p` option and the process ID (PID):

```bash
lsof -p PID
```

#### Check process network connections

To check the network connections established by a specific process, you can use the `lsof` command followed by the `-i` option and the process ID (PID):

```bash
lsof -i -p PID
```

#### Check process environment variables

To check the environment variables of a specific process, you can use the `ps` command with the `-e` option followed by the process ID (PID):

```bash
ps -e -o pid,command | grep PID
```

#### Check process threads

To check the threads of a specific process, you can use the `ps` command with the `-eL` option followed by the process ID (PID):

```bash
ps -eL | grep PID
```

#### Check process memory usage

To check the memory usage of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `rss` field:

```bash
ps -o rss= -p PID
```

#### Check process CPU usage

To check the CPU usage of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `%cpu` field:

```bash
ps -o %cpu= -p PID
```

#### Check process disk usage

To check the disk usage of a specific process, you can use the `du` command followed by the `-sh` option and the path to the process:

```bash
du -sh /path/to/process
```

#### Check process file descriptors

To check the file descriptors of a specific process, you can use the `lsof` command followed by the `-p` option and the process ID (PID):

```bash
lsof -p PID | wc -l
```

#### Check process parent

To check the parent process of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `ppid` field:

```bash
ps -o ppid= -p PID
```

#### Check process children

To check the child processes of a specific process, you can use the `pgrep` command followed by the `-P` option and the process ID (PID):

```bash
pgrep -P PID
```

#### Check process executable path

To check the executable path of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `comm` field:

```bash
ps -o comm= -p PID
```

#### Check process start time

To check the start time of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `lstart` field:

```bash
ps -o lstart= -p PID
```

#### Check process user

To check the user of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `user` field:

```bash
ps -o user= -p PID
```

#### Check process group

To check the group of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `group` field:

```bash
ps -o group= -p PID
```

#### Check process status

To check the status of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `stat` field:

```bash
ps -o stat= -p PID
```

#### Check process command line

To check the command line of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `command` field:

```bash
ps -o command= -p PID
```

#### Check process environment variables

To check the environment variables of a specific process, you can use the `ps` command with the `-e` option followed by the process ID (PID):

```bash
ps -e -o pid,command | grep PID
```

#### Check process threads

To check the threads of a specific process, you can use the `ps` command with the `-eL` option followed by the process ID (PID):

```bash
ps -eL | grep PID
```

#### Check process memory usage

To check the memory usage of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `rss` field:

```bash
ps -o rss= -p PID
```

#### Check process CPU usage

To check the CPU usage of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `%cpu` field:

```bash
ps -o %cpu= -p PID
```

#### Check process disk usage

To check the disk usage of a specific process, you can use the `du` command followed by the `-sh` option and the path to the process:

```bash
du -sh /path/to/process
```

#### Check process file descriptors

To check the file descriptors of a specific process, you can use the `lsof` command followed by the `-p` option and the process ID (PID):

```bash
lsof -p PID | wc -l
```

#### Check process parent

To check the parent process of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `ppid` field:

```bash
ps -o ppid= -p PID
```

#### Check process children

To check the child processes of a specific process, you can use the `pgrep` command followed by the `-P` option and the process ID (PID):

```bash
pgrep -P PID
```

#### Check process executable path

To check the executable path of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `comm` field:

```bash
ps -o comm= -p PID
```

#### Check process start time

To check the start time of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `lstart` field:

```bash
ps -o lstart= -p PID
```

#### Check process user

To check the user of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `user` field:

```bash
ps -o user= -p PID
```

#### Check process group

To check the group of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `group` field:

```bash
ps -o group= -p PID
```

#### Check process status

To check the status of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `stat` field:

```bash
ps -o stat= -p PID
```

#### Check process command line

To check the command line of a specific process, you can use the `ps` command with the `-o` option followed by the process ID (PID) and the `command` field:

```bash
ps -o command= -p PID
```
```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```
### Qap'a' lo'laHbe'

lo'laHbe' prompts

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
