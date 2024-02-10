# UTS Namespace

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Basic Information

A UTS (UNIX Time-Sharing System) namespace is a Linux kernel feature that provides i**solation of two system identifiers**: the **hostname** and the **NIS** (Network Information Service) domain name. This isolation allows each UTS namespace to have its **own independent hostname and NIS domain name**, which is particularly useful in containerization scenarios where each container should appear as a separate system with its own hostname.

### How it works:

1. When a new UTS namespace is created, it starts with a **copy of the hostname and NIS domain name from its parent namespace**. This means that, at creation, the new namespace s**hares the same identifiers as its parent**. However, any subsequent changes to the hostname or NIS domain name within the namespace will not affect other namespaces.
2. Processes within a UTS namespace **can change the hostname and NIS domain name** using the `sethostname()` and `setdomainname()` system calls, respectively. These changes are local to the namespace and do not affect other namespaces or the host system.
3. Processes can move between namespaces using the `setns()` system call or create new namespaces using the `unshare()` or `clone()` system calls with the `CLONE_NEWUTS` flag. When a process moves to a new namespace or creates one, it will start using the hostname and NIS domain name associated with that namespace.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
**QIb**: `/proc` filesystem jImejDaq `--mount-proc` param jImejDaq, **namespace** vItlhutlh **process information** vItlhutlh **accurate and isolated view** jImejDaq **ensure**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

`unshare` `-f` option vItlhutlh, Linux **new PID (Process ID) namespaces** vItlhutlh **way** vItlhutlh **error** vItlhutlh:

1. **Problem Explanation**:
- Linux kernel **process** vItlhutlh `unshare` **new namespaces** vItlhutlh **creation** vItlhutlh **allow**. However, **process** vItlhutlh **new PID namespace** vItlhutlh **enter**; **child processes** vItlhutlh.
- `%unshare -p /bin/bash%` **run** `/bin/bash` **process** `unshare` **process** vItlhutlh **start**. Consequently, `/bin/bash` **child processes** vItlhutlh **original PID namespace** vItlhutlh.
- `/bin/bash` **new namespace** **first child process** PID 1 vItlhutlh. **process** vItlhutlh **exit**, **namespace** vItlhutlh **cleanup** vItlhutlh **trigger** vItlhutlh **no other processes** vItlhutlh, PID 1 **orphan processes** vItlhutlh **adopt** vItlhutlh **special role** vItlhutlh. Linux kernel vItlhutlh **PID allocation** vItlhutlh **disable** vItlhutlh **namespace** vItlhutlh.

2. **Consequence**:
- **new namespace** PID 1 **exit**, `PIDNS_HASH_ADDING` **flag** vItlhutlh **cleaning** vItlhutlh. `alloc_pid` **function** vItlhutlh **new PID** vItlhutlh **allocate** vItlhutlh **new process** vItlhutlh **create**, "Cannot allocate memory" **error** vItlhutlh.

3. **Solution**:
- `-f` **option** vItlhutlh `unshare` **use** vItlhutlh **issue** vItlhutlh **resolve**. `unshare` **new PID namespace** vItlhutlh **create** vItlhutlh **after** **fork** vItlhutlh **new process** vItlhutlh.
- `%unshare -fp /bin/bash%` **execute**, `unshare` **command** PID 1 **new namespace** vItlhutlh. `/bin/bash` **child processes** vItlhutlh **safely contained** vItlhutlh **new namespace**, PID 1 **premature exit** vItlhutlh **prevent** vItlhutlh **normal PID allocation** vItlhutlh.

`unshare` **run** `-f` **flag** vItlhutlh, **new PID namespace** vItlhutlh **correctly maintained**, `/bin/bash` **sub-processes** vItlhutlh **operate** vItlhutlh **memory allocation error** vItlhutlh **encounter**.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Check which namespace is your process in

#### English Translation:

### &#x20;QaStaHvIS namespace vItlhutlh

#### Klingon Translation:

### &#x20;QaStaHvIS namespace vItlhutlh
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Qapvam UTS namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Qa'chu' 'ej UTS namespace

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
### Change hostname

### qo' vItlhutlh

The hostname of a system can be changed by modifying the UTS (Unix Time-Sharing) namespace. This namespace is responsible for providing a unique identifier for the system's hostname.

To change the hostname, you need to perform the following steps:

1. Obtain root privileges.
2. Obtain a descriptor pointing to the UTS namespace you want to modify. This can be done by accessing the `/proc/self/ns/uts` file.
3. Use the `sethostname()` system call to change the hostname within the UTS namespace.

Keep in mind that you can only enter another process namespace if you are root, and you cannot enter another namespace without a descriptor pointing to it (like `/proc/self/ns/uts`).

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo' vItlhutlh

### qo'
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
## References
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
