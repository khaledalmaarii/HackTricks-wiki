# CGroup Namespace

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

A cgroup namespace is a Linux kernel feature that provides **isolation of cgroup hierarchies for processes running within a namespace**. Cgroups, short for **control groups**, are a kernel feature that allows organizing processes into hierarchical groups to manage and enforce **limits on system resources** like CPU, memory, and I/O.

While cgroup namespaces are not a separate namespace type like the others we discussed earlier (PID, mount, network, etc.), they are related to the concept of namespace isolation. **Cgroup namespaces virtualize the view of the cgroup hierarchy**, so that processes running within a cgroup namespace have a different view of the hierarchy compared to processes running in the host or other namespaces.

### How it works:

1. When a new cgroup namespace is created, **it starts with a view of the cgroup hierarchy based on the cgroup of the creating process**. This means that processes running in the new cgroup namespace will only see a subset of the entire cgroup hierarchy, limited to the cgroup subtree rooted at the creating process's cgroup.
2. Processes within a cgroup namespace will **see their own cgroup as the root of the hierarchy**. This means that, from the perspective of processes inside the namespace, their own cgroup appears as the root, and they cannot see or access cgroups outside of their own subtree.
3. Cgroup namespaces do not directly provide isolation of resources; **they only provide isolation of the cgroup hierarchy view**. **Resource control and isolation are still enforced by the cgroup** subsystems (e.g., cpu, memory, etc.) themselves.

For more information about CGroups check:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
**QawHaq**: `/proc` filesystem jImejDaq `--mount-proc` param vItlhutlh, vaj **ghItlhvam je vItlhutlh vay' process vItlhutlhDaq jImejDaq vay' process vItlhutlhDaq vay' jImejDaq** vItlhutlh.

<details>

<summary>Qagh: bash: fork: Cannot allocate memory</summary>

`unshare` `-f` option vItlhutlhDaq, Linux vItlhutlhDaq vay' PID (Process ID) jImejDaq vItlhutlhDaqDaq vItlhutlhDaqDaq vItlhutlhDaqDaq vItlhutlhDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaq
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Check which namespace is your process in

### &#x20;qaStaHvIS namespace vItlhutlh

To check which namespace your process is in, you can use the `lsns` command. This command lists all the namespaces on the system along with their associated processes.

```bash
lsns
```

The output will display the namespace ID, type, and the number of processes associated with each namespace. Look for the process ID (PID) of your process in the output to determine which namespace it belongs to.

If you want to filter the output to only show the namespaces associated with your process, you can use the `ps` command along with the `--pid` option.

```bash
ps --pid <PID> -o ns
```

Replace `<PID>` with the process ID of your process. The output will show the namespaces associated with that process.

By checking the namespace of your process, you can gain a better understanding of the isolation and security boundaries in place.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### bIyIntaHvIS CGroup namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Qa'chuq CGroup namespace

{% code-tabs %}
{% code-tabs-item title="C" %}
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];

static int child_func(void *arg) {
    printf("### Inside the child namespace ###\n");
    system("ls /");

    return 0;
}

int main() {
    printf("### Before creating the child namespace ###\n");
    system("ls /");

    pid_t child_pid = clone(child_func, child_stack + STACK_SIZE, CLONE_NEWCGROUP | SIGCHLD, NULL);
    if (child_pid == -1) {
        perror("clone");
        return 1;
    }

    printf("### After creating the child namespace ###\n");

    if (waitpid(child_pid, NULL, 0) == -1) {
        perror("waitpid");
        return 1;
    }

    return 0;
}
```
{% endcode-tabs-item %}
{% endcode-tabs %}

The above C program demonstrates how to enter inside a CGroup namespace. It creates a child process using the `clone()` system call with the `CLONE_NEWCGROUP` flag, which creates a new CGroup namespace for the child process. The child process then executes a command (`ls /`) inside its own namespace.

To compile and run the program, save it to a file (e.g., `cgroup_namespace.c`) and use the following commands:

```bash
gcc -o cgroup_namespace cgroup_namespace.c
./cgroup_namespace
```

When running the program, you will see the output before and after creating the child namespace. The command executed inside the child namespace (`ls /`) will only show the root directory (`/`) contents within that namespace, isolating it from the parent namespace.
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
**ghItlh** **enter** **ghItlh** **process namespace** **vaj** **root** **'e'**. **'ej** **ghItlh** **enter** **'ej** **namespace** **ghItlh** **descriptor** **'e'** **pointing** **(like `/proc/self/ns/cgroup`)**.

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
