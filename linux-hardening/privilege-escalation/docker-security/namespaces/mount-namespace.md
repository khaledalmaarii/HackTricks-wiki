# Mount Namespace

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

A mount namespace is a Linux kernel feature that provides isolation of the file system mount points seen by a group of processes. Each mount namespace has its own set of file system mount points, and **changes to the mount points in one namespace do not affect other namespaces**. This means that processes running in different mount namespaces can have different views of the file system hierarchy.

Mount namespaces are particularly useful in containerization, where each container should have its own file system and configuration, isolated from other containers and the host system.

### How it works:

1. When a new mount namespace is created, it is initialized with a **copy of the mount points from its parent namespace**. This means that, at creation, the new namespace shares the same view of the file system as its parent. However, any subsequent changes to the mount points within the namespace will not affect the parent or other namespaces.
2. When a process modifies a mount point within its namespace, such as mounting or unmounting a file system, the **change is local to that namespace** and does not affect other namespaces. This allows each namespace to have its own independent file system hierarchy.
3. Processes can move between namespaces using the `setns()` system call, or create new namespaces using the `unshare()` or `clone()` system calls with the `CLONE_NEWNS` flag. When a process moves to a new namespace or creates one, it will start using the mount points associated with that namespace.
4. **File descriptors and inodes are shared across namespaces**, meaning that if a process in one namespace has an open file descriptor pointing to a file, it can **pass that file descriptor** to a process in another namespace, and **both processes will access the same file**. However, the file's path may not be the same in both namespaces due to differences in mount points.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
**QIb** `/proc` filesystem jImejDaq `--mount-proc` param vIleghlaH, **ghItlhvam je** namespace vItlhutlhlaHvIS **ghItlhvam je** process vItlhutlhlaHvIS **ghItlhvam je** jImejDaq vItlhutlhlaHvIS **ghItlhvam je** accurate 'ej **ghItlhvam je** jImejDaq vItlhutlhlaHvIS **ghItlhvam je** process vItlhutlhlaHvIS **ghItlhvam je** namespace vItlhutlhlaHvIS.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

`unshare` `-f` option vIleghlaHghach, Linux jImejDaq vItlhutlhlaHvIS **ghItlhvam je** PID (Process ID) namespace vItlhutlhlaHvIS. **ghItlhvam je** jImejDaq 'ej **ghItlhvam je** jImejDaq vItlhutlhlaHvIS **ghItlhvam je** jImejDaq vItlhutlhlaHvIS **ghItlhvam je** PID namespace vItlhutlhlaHvIS.

1. **QaH Explanation**:
- Linux jImejDaq vItlhutlhlaHvIS `unshare` system call vIleghlaH, jImejDaq vItlhutlhlaHvIS **ghItlhvam je** namespace vItlhutlhlaHvIS. 'ach, jImejDaq vItlhutlhlaHvIS namespace vItlhutlhlaHvIS **ghItlhvam je** process vItlhutlhlaHvIS; 'ej **ghItlhvam je** child process vItlhutlhlaHvIS.
- `%unshare -p /bin/bash%` vIleghlaHghach `/bin/bash` jImejDaq vItlhutlhlaHvIS `unshare` jImejDaq vItlhutlhlaHvIS. vaj 'ach, `/bin/bash` 'ej **ghItlhvam je** child process vItlhutlhlaHvIS **ghItlhvam je** original PID namespace vItlhutlhlaHvIS.
- jImejDaq vItlhutlhlaHvIS namespace vItlhutlhlaHvIS **ghItlhvam je** child process vItlhutlhlaHvIS PID 1 vItlhutlhlaHvIS. vaj, jImejDaq vItlhutlhlaHvIS process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **ghItlhvam je** 'ej **ghItlhvam je** process vItlhutlhlaHvIS, PID 1 vItlhutlhlaHvIS **
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Check which namespace is your process in

#### English Translation

### &#x20;QaStaHvIS namespace vItlhutlh

#### Klingon Translation

### &#x20;QaStaHvIS namespace vItlhutlh
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Qapvam namespace 'ej

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Qa'vam vItlhutlh

{% code-tabs %}
{% code-tabs-item title="C++" %}
```cpp
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/mount.h>

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];

int child_function(void *arg) {
    printf("### Inside the child namespace ###\n");
    system("ls /"); // Run any command inside the child namespace
    return 0;
}

int main() {
    printf("### Before creating the child namespace ###\n");
    int child_pid = clone(child_function, child_stack + STACK_SIZE, CLONE_NEWNS | SIGCHLD, NULL);
    if (child_pid == -1) {
        perror("clone");
        return 1;
    }
    printf("### After creating the child namespace ###\n");
    sleep(1); // Wait for the child process to finish
    return 0;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

To enter inside a mount namespace, we can use the `clone()` system call with the `CLONE_NEWNS` flag. This will create a new child process with its own mount namespace. The `SIGCHLD` flag is used to automatically reap the child process after it exits.

In the example code above, we define a `child_function()` that will be executed inside the child namespace. We print a message to indicate that we are inside the child namespace and then run any command using the `system()` function.

To run the code, compile it using `gcc` and execute the resulting binary:

```bash
gcc -o mount_namespace mount_namespace.c
./mount_namespace
```

You will see the output of the command executed inside the child namespace.
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
**qaStaHvIS** **root** **ghItlh** **namespace** **process** **bIquv**. **'ej** **'oH** **namespace** **'e'** **ghItlh** **descriptor** **bIquv** **(vaj** `/proc/self/ns/mnt` **laH**).

**vItlhutlh** **mounts** **jatlh** **namespace** **Dochmey** **qay'** **ghItlh** **information** **Sop** **'e'** **ghItlh** **accessible** **bIquv**.

### **Something** **Mount**
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
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
