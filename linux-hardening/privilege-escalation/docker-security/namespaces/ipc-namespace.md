# IPC Namespace

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

An IPC (Inter-Process Communication) namespace is a Linux kernel feature that provides **isolation** of System V IPC objects, such as message queues, shared memory segments, and semaphores. This isolation ensures that processes in **different IPC namespaces cannot directly access or modify each other's IPC objects**, providing an additional layer of security and privacy between process groups.

### How it works:

1. When a new IPC namespace is created, it starts with a **completely isolated set of System V IPC objects**. This means that processes running in the new IPC namespace cannot access or interfere with the IPC objects in other namespaces or the host system by default.
2. IPC objects created within a namespace are visible and **accessible only to processes within that namespace**. Each IPC object is identified by a unique key within its namespace. Although the key may be identical in different namespaces, the objects themselves are isolated and cannot be accessed across namespaces.
3. Processes can move between namespaces using the `setns()` system call or create new namespaces using the `unshare()` or `clone()` system calls with the `CLONE_NEWIPC` flag. When a process moves to a new namespace or creates one, it will start using the IPC objects associated with that namespace.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
**QawHaq**: `/proc` filesystem jImejDaq `--mount-proc` param vItlhutlh, **ghItlhvam je Dujvam vItlhutlh**. 

<details>

<summary>Qagh: bash: fork: memory vItlhutlh</summary>

`unshare` `-f` option vItlhutlh, Linux jImejDaq vItlhutlh PID (Process ID) namespace vItlhutlh. vItlhutlh je je vItlhutlh PID namespace vItlhutlh (ghItlhvam "unshare" vItlhutlh) vItlhutlh, vItlhutlh vItlhutlh namespace vItlhutlh; vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh.
`%unshare -p /bin/bash%` `%unshare -p /bin/bash%` `/bin/bash` vItlhutlh `unshare` vItlhutlh. `/bin/bash` vItlhutlh vItlhutlh vItlhutlh vItlhutlh PID namespace vItlhutlh.
`/bin/bash` vItlhutlh vItlhutlh vItlhutlh PID 1 vItlhutlh. vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhut
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Check which namespace is your process in

### &#x20;qaStaHvIS namespace vItlhutlh

To check which namespace your process is in, you can use the following command:

```bash
$ cat /proc/$$/ns/ipc
```

This will display the inode number of the IPC namespace that your process is currently in.
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### bIqetlh IPC namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Qa'chuq IPC namespace

To enter inside an IPC namespace, you can use the `ip` command with the `netns` option. First, you need to find the PID of a process that is running inside the target IPC namespace. You can do this by running the `ps` command with the `--pid` option and specifying the PID of the target process. Once you have the PID, you can use the `ip` command to enter the IPC namespace by running the following command:

```
ip netns exec <PID> /bin/bash
```

Replace `<PID>` with the actual PID of the target process. This will open a new shell inside the IPC namespace, allowing you to execute commands and interact with the processes running inside the namespace.

Note that you need root privileges to enter an IPC namespace. If you don't have root access, you can try exploiting a vulnerability or misconfiguration to gain root privileges and then enter the IPC namespace.
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
### QapwI'pu' 'e' yIlo' 'ej 'oH 'e' yIqaw'egh

### Create IPC chegh

QapwI'pu' 'e' yIlo' 'ej 'oH 'e' yIqaw'egh. 'ej **root** 'oH **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'oH** **'o
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
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
