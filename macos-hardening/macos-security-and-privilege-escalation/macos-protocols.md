# macOS Network Services & Protocols

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Remote Access Services

These are the common macOS services to access them remotely.\
You can enable/disable these services in `System Settings` --> `Sharing`

* **VNC**, known as “Screen Sharing” (tcp:5900)
* **SSH**, called “Remote Login” (tcp:22)
* **Apple Remote Desktop** (ARD), or “Remote Management” (tcp:3283, tcp:5900)
* **AppleEvent**, known as “Remote Apple Event” (tcp:3031)

Check if any is enabled running:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) is an enhanced version of [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) tailored for macOS, offering additional features. A notable vulnerability in ARD is its authentication method for the control screen password, which only uses the first 8 characters of the password, making it prone to [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) with tools like Hydra or [GoRedShell](https://github.com/ahhh/GoRedShell/), as there are no default rate limits.

Vulnerable instances can be identified using **nmap**'s `vnc-info` script. Services supporting `VNC Authentication (2)` are especially susceptible to brute force attacks due to the 8-character password truncation.

To enable ARD for various administrative tasks like privilege escalation, GUI access, or user monitoring, use the following command:

```
<code>
```
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
## Bonjour Protocol

Bonjour, ngeD Apple, **ghItlh** **devices on the same network to detect each other's offered services**. Known also as Rendezvous, **Zero Configuration**, or Zeroconf, it enables a device to join a TCP/IP network, **automatically choose an IP address**, and broadcast its services to other network devices.

Zero Configuration Networking, provided by Bonjour, ensures that devices can:
* **Automatically obtain an IP Address** even in the absence of a DHCP server.
* Perform **name-to-address translation** without requiring a DNS server.
* **Discover services** available on the network.

Devices using Bonjour will assign themselves an **IP address from the 169.254/16 range** and verify its uniqueness on the network. Macs maintain a routing table entry for this subnet, verifiable via `netstat -rn | grep 169`.

For DNS, Bonjour utilizes the **Multicast DNS (mDNS) protocol**. mDNS operates over **port 5353/UDP**, employing **standard DNS queries** but targeting the **multicast address 224.0.0.251**. This approach ensures that all listening devices on the network can receive and respond to the queries, facilitating the update of their records.

Upon joining the network, each device self-selects a name, typically ending in **.local**, which may be derived from the hostname or randomly generated.

Service discovery within the network is facilitated by **DNS Service Discovery (DNS-SD)**. Leveraging the format of DNS SRV records, DNS-SD uses **DNS PTR records** to enable the listing of multiple services. A client seeking a specific service will request a PTR record for `<Service>.<Domain>`, receiving in return a list of PTR records formatted as `<Instance>.<Service>.<Domain>` if the service is available from multiple hosts.


The `dns-sd` utility can be employed for **discovering and advertising network services**. Here are some examples of its usage:

### Searching for SSH Services

To search for SSH services on the network, the following command is used:
```bash
dns-sd -B _ssh._tcp
```
**ghItlh** **command** **vItlhutlh** _ssh._tcp **services** **browsing** **initiates** **command** **This** **details** **outputs** **name** **instance** **type** **service** **domain** **interface** **flags** **timestamp**.

### **HTTP** **Service** **an** **Advertising**

**HTTP** **an** **advertise** **To**, **use** **can** **service**.
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
**Translation (Klingon):**

```
Qapvam HTTP service "Index" yInID 80 port vaj path `/index.html` DaH jImej.

vaj HTTP service DeSDu' network DaH search:
```
```bash
dns-sd -B _http._tcp
```
QaStaHvIS, cha'loghDaq Daqawlu'chugh, 'ej Daqawlu'chughDI' Daqawlu'chughDI' qonwI'pu' 'e' yIqaw. Daqawlu'chughDI' qonwI'pu' 'e' vItlhutlh.

**Discovery - DNS-SD Browser** app, Apple App StoreDaq jImej, lo'laHbe'lu'chughDI' qonwI'pu' 'e' vItlhutlh.

Qapbe'lu'chughDI' qonwI'pu' 'e' vItlhutlh, 'ej 'oH python-zeroconf libraryDaq Qapbe'lu'chughDI' qonwI'pu' 'e' vItlhutlh. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script, `_http._tcp.local.` qonwI'pu' 'e' vItlhutlh, qonwI'pu' jImejDaq 'oH, qonwI'pu' jImejDaq vItlhutlh.
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Bonjour jatlh
Qap concerns security pagh vaj reasons disable Bonjour, 'ej 'ej command lo'laHbe' 'e' vItlhutlh:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
