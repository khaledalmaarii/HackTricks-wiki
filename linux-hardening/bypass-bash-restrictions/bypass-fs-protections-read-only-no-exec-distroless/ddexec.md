# DDexec / EverythingExec

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Context

In Linux in order to run a program it must exist as a file, it must be accessible in some way through the file system hierarchy (this is just how `execve()` works). This file may reside on disk or in ram (tmpfs, memfd) but you need a filepath. This has made very easy to control what is run on a Linux system, it makes easy to detect threats and attacker's tools or to prevent them from trying to execute anything of theirs at all (_e. g._ not allowing unprivileged users to place executable files anywhere).

But this technique is here to change all of this. If you can not start the process you want... **then you hijack one already existing**.

This technique allows you to **bypass common protection techniques such as read-only, noexec, file-name whitelisting, hash whitelisting...**

## Dependencies

The final script depends on the following tools to work, they need to be accessible in the system you are attacking (by default you will find all of them everywhere):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Qap

QapmeywI'pu' 'e' yIqaw, 'ej qapmeywI'pu' 'e' yIqaw, 'ach 'oH vItlhutlh. vaj 'oH vItlhutlh vay' 'e' vItlhutlh 'ej vItlhutlh vay' 'e' vItlhutlh. vaj, 'oH vItlhutlh vay' 'e' vItlhutlh 'ej `/proc/$pid/mem` DaH jImej. 'ej vaj, 'oH vItlhutlh vay' 'e' vItlhutlh 'ej `/proc/$pid/mem` DaH jImej. 

`/proc/$pid/mem` vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' vItlhutlh vay' 'e' v
```bash
tail
hexdump
cmp
xxd
```
`SEEKER` ghom vItlhutlh. vItlhutlhmo' Seeker, _e. g._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
**ghItlhvam**:
vaj 'SEEKER_ARGS' **ghItlh** vay' **script** DaH jImej. vaj 'SEEKER_ARGS' **ghItlhvam** **vay'**.
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
jIyajbe', EDRs.

## References
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>laH</strong></a><strong>!</strong></summary>

HackTricks vItlhutlh:

* **HackTricks** vItlhutlh **tlhIngan Hol** **company** **advertised** **want** **or** **HackTricks** **PDF** **download** **to** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **Check**!
* **PEASS & HackTricks swag** [**official**](https://peass.creator-spring.com) **Get**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, **exclusive NFTs** [**our collection**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **or the** [**telegram group**](https://t.me/peass) **or** **follow** **us on** **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) **and** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>
