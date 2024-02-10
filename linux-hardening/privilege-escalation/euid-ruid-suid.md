# euid, ruid, suid

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>! HackTricks</strong></a><strong>!</strong></summary>

* **Do you work in a cybersecurity company**? **Do you want to see your company advertised in HackTricks**? **or do you want to have access to the latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### User Identification Variables

- **`ruid`**: **real user ID** denotes the user who initiated the process.
- **`euid`**: **effective user ID**, represents the user identity utilized by the system to ascertain process privileges. Generally, `euid` mirrors `ruid`, barring instances like a SetUID binary execution, where `euid` assumes the file owner's identity, thus granting specific operational permissions.
- **`suid`**: **saved user ID** is pivotal when a high-privilege process (typically running as root) needs to temporarily relinquish its privileges to perform certain tasks, only to later reclaim its initial elevated status.

#### Important Note
A process not operating under root can only modify its `euid` to match the current `ruid`, `euid`, or `suid`.

### Understanding set*uid Functions

- **`setuid`**: Contrary to initial assumptions, `setuid` primarily modifies `euid` rather than `ruid`. Specifically, for privileged processes, it aligns `ruid`, `euid`, and `suid` with the specified user, often root, effectively solidifying these IDs due to the overriding `suid`. Detailed insights can be found in the [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** and **`setresuid`**: These functions allow for the nuanced adjustment of `ruid`, `euid`, and `suid`. However, their capabilities are contingent on the process's privilege level. For non-root processes, modifications are restricted to the current values of `ruid`, `euid`, and `suid`. In contrast, root processes or those with `CAP_SETUID` capability can assign arbitrary values to these IDs. More information can be gleaned from the [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) and the [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

These functionalities are designed not as a security mechanism but to facilitate the intended operational flow, such as when a program adopts another user's identity by altering its effective user ID.

Notably, while `setuid` might be a common go-to for privilege elevation to root (since it aligns all IDs to root), differentiating between these functions is crucial for understanding and manipulating user ID behaviors in varying scenarios.

### Program Execution Mechanisms in Linux

#### **`execve` System Call**
- **Functionality**: `execve` initiates a program, determined by the first argument. It takes two array arguments, `argv` for arguments and `envp` for the environment.
- **Behavior**: It retains the memory space of the caller but refreshes the stack, heap, and data segments. The program's code is replaced by the new program.
- **User ID Preservation**:
- `ruid`, `euid`, and supplementary group IDs remain unaltered.
- `euid` might have nuanced changes if the new program has the SetUID bit set.
- `suid` gets updated from `euid` post-execution.
- **Documentation**: Detailed information can be found on the [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Function**
- **Functionality**: Unlike `execve`, `system` creates a child process using `fork` and executes a command within that child process using `execl`.
- **Command Execution**: Executes the command via `sh` with `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: As `execl` is a form of `execve`, it operates similarly but in the context of a new child process.
- **Documentation**: Further insights can be obtained from the [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior of `bash` and `sh` with SUID**
- **`bash`**:
- Has a `-p` option influencing how `euid` and `ruid` are treated.
- Without `-p`, `bash` sets `euid` to `ruid` if they initially differ.
- With `-p`, the initial `euid` is preserved.
- More details can be found on the [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Does not possess a mechanism similar to `-p` in `bash`.
- The behavior concerning user IDs is not explicitly mentioned, except under the `-i` option, emphasizing the preservation of `euid` and `ruid` equality.
- Additional information is available on the [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

These mechanisms, distinct in their operation, offer a versatile range of options for executing and transitioning between programs, with specific nuances in how user IDs are managed and preserved.

### Testing User ID Behaviors in Executions

Examples taken from https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, check it for further information

#### Case 1: Using `setuid` with `system`

**Objective**: Understanding the effect of `setuid` in combination with `system` and `bash` as `sh`.

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Qa'vam je Permissions:**

When a program is compiled, it is assigned certain permissions that determine what actions it can perform on the system. These permissions are associated with the program's Effective User ID (EUID), Real User ID (RUID), and Set User ID (SUID).

- **EUID (Qa'vam je User ID):** The EUID is the user ID that the program runs with when it is executed. It determines the permissions that the program has while running. By default, the EUID is set to the user who executed the program.

- **RUID (Qa'vam je User ID):** The RUID is the user ID that owns the program file. It determines the permissions that the program has when it is accessed or modified. By default, the RUID is set to the user who created the program file.

- **SUID (Qa'vam je User ID):** The SUID is a special permission that can be set on a program file. When a program with SUID is executed, it runs with the permissions of the file's owner, rather than the user who executed it. This can be useful for allowing certain users to perform actions that require elevated privileges.

Understanding these permissions is important for both system administrators and hackers. System administrators need to ensure that programs are compiled with the appropriate permissions to maintain system security. Hackers, on the other hand, can exploit programs with incorrect or insecure permissions to escalate their privileges and gain unauthorized access to the system.

**Qa'vam je Permissions:**

DaH jatlhlaHbe'chugh, program 'e' vItlhutlhlaH permissions vItlhutlh. permissions 'e' program 'e' Effective User ID (EUID), Real User ID (RUID), je Set User ID (SUID) vItlhutlh.

- **EUID (Qa'vam je User ID):** EUID 'e' program 'e' vItlhutlhlaHbe'chugh qa'vam je User ID. 'Iv program 'e' vItlhutlhlaHbe'chugh permissions vItlhutlh. DaH jatlhlaHbe'chugh, EUID vItlhutlhlaHbe'chugh program 'e' vItlhutlhlaHbe'chugh user.

- **RUID (Qa'vam je User ID):** RUID 'e' program file 'e' vItlhutlhlaHbe'chugh qa'vam je User ID. 'Iv program file 'e' vItlhutlhlaHbe'chugh permissions vItlhutlh. DaH jatlhlaHbe'chugh, RUID vItlhutlhlaHbe'chugh program file 'e' vItlhutlhlaHbe'chugh user.

- **SUID (Qa'vam je User ID):** SUID 'e' program file 'e' vItlhutlhlaHbe'chugh permissions. program SUID vItlhutlhlaHbe'chugh, 'Iv program 'e' vItlhutlhlaHbe'chugh, 'Iv program 'e' vItlhutlhlaHbe'chugh file 'e' vItlhutlhlaHbe'chugh owner permissions, vaj user 'e' vItlhutlhlaHbe'chugh. vItlhutlhlaHbe'chugh SUID, Hoch vItlhutlhlaHbe'chugh users vItlhutlhlaHbe'chugh actions vajwI' elevated privileges.

permissions 'e' vItlhutlhlaHbe'chugh 'e' vItlhutlhlaHbe'chugh system administrators je hackers. system administrators vItlhutlhlaHbe'chugh programs vItlhutlhlaHbe'chugh permissions vItlhutlhlaHbe'chugh maintain system security. Hackers, 'ej, vaj, programs vItlhutlhlaHbe'chugh incorrect vaj 'ej vItlhutlhlaHbe'chugh permissions vItlhutlhlaHbe'chugh, vItlhutlhlaHbe'chugh 'ej unauthorized access vItlhutlhlaHbe'chugh system.
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Qap:**

* `ruid` 'ej `euid` 99 (nobody) 'ej 1000 (frank) jay'.
* `setuid` cha'logh 1000.
* `system` `/bin/bash -c id` 'ej `/bin/bash` vItlhutlh.
* `bash`, `-p` Hoch, `euid` 'ej `ruid` jay' 'ej 99 (nobody) jay'. 

#### Case 2: setreuid jatlh system jatlh
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**QapHa'wI' je Permissions:**

When a program is compiled, it is assigned certain permissions that determine what actions it can perform on the system. These permissions are associated with the program's executable file and are set using the chmod command.

**QapHa'wI' je Permissions:**

DaH jatlhlaHbe'chugh, program 'e' vItlhutlhlaHchugh, 'e' vItlhutlhlaHchugh permissions vItlhutlhlaHchugh, 'e' vItlhutlhlaHchugh vay' executable file 'ej chmod command vItlhutlhlaHchugh.
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Qap**:

The **euid** (Effective User ID), **ruid** (Real User ID), and **suid** (Saved User ID) are important concepts in Linux that relate to user privileges and privilege escalation.

The **euid** represents the effective user ID of a process, which determines the permissions and privileges that the process has. It is used to determine the access rights of the process when interacting with files, directories, and other system resources.

The **ruid** represents the real user ID of a process, which is the user ID of the user who executed the process. It is used to determine the initial access rights of the process.

The **suid** represents the saved user ID of a process, which is used to temporarily switch the effective user ID to the real user ID. This is commonly used when a process needs to perform certain actions with elevated privileges, but then needs to revert back to its original privileges.

Understanding the relationship between these IDs is crucial for privilege escalation techniques. By manipulating the euid, ruid, and suid values, an attacker can potentially gain elevated privileges and perform unauthorized actions on a system.

It is important to note that privilege escalation techniques should only be used for ethical purposes, such as penetration testing or securing systems against potential attacks. Unauthorized use of these techniques is illegal and can result in severe consequences.

To learn more about privilege escalation techniques and how to defend against them, refer to the relevant resources and documentation available.
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Qap:**

* `setreuid` ruid je euid je 1000.
* `system` bash vaj invokes, vaj rur IDs vaj, vaj 'ej vaj, vaj frank vaj.

#### Case 3: setuid vaj execve vaj
Qap: Exploring vaj interaction vaj setuid vaj execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Qap**:

The **euid** (Effective User ID), **ruid** (Real User ID), and **suid** (Saved User ID) are important concepts in Linux that relate to user privileges and privilege escalation.

The **euid** represents the effective user ID of a process, which determines the permissions and privileges that the process has. It is used to determine the access rights of the process when interacting with files, directories, and other system resources.

The **ruid** represents the real user ID of a process, which is the user ID of the user who executed the process. It is used to determine the initial access rights of the process.

The **suid** represents the saved user ID of a process, which is used to temporarily switch the effective user ID to the real user ID. This is commonly used when a process needs to perform certain actions with elevated privileges, but then needs to revert back to its original privileges.

Understanding the relationship between these IDs is crucial for privilege escalation techniques. By manipulating the euid, ruid, and suid values, an attacker can potentially gain elevated privileges and perform unauthorized actions on a system.

To check the current values of these IDs for a process, you can use the `id` command with the `-u` option:

```bash
id -u
```

To change the euid, ruid, or suid values of a process, you can use the `setuid()` and `seteuid()` system calls in C programming. However, keep in mind that these calls require root privileges to be executed successfully.

It's important to note that manipulating these IDs without proper authorization is considered a security vulnerability and can lead to unauthorized access and malicious activities. Therefore, it's crucial to implement proper security measures and hardening techniques to prevent privilege escalation attacks.
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Qap:**

* `ruid` 99, 'ej'e'ID 1000, 'ej' setuid'e' vItlhutlh.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Qap**:

The **euid** (Effective User ID), **ruid** (Real User ID), and **suid** (Saved User ID) are important concepts in Linux that relate to user privileges and privilege escalation.

The **euid** represents the effective user ID of a process, which determines the permissions and privileges that the process has. It is used to determine the access rights of the process when interacting with files, directories, and other system resources.

The **ruid** represents the real user ID of a process, which is the user ID of the user who executed the process. It is used to determine the initial access rights of the process.

The **suid** represents the saved user ID of a process, which is used to temporarily switch the effective user ID to the real user ID. This is commonly used when a process needs to perform certain actions with elevated privileges, but then needs to revert back to its original privileges.

Understanding the relationship between these IDs is crucial for privilege escalation techniques. By manipulating the euid, ruid, and suid values, an attacker can potentially gain elevated privileges and perform unauthorized actions on a system.

It is important to note that privilege escalation techniques should only be used for ethical purposes, such as penetration testing or securing systems against potential attacks. Unauthorized use of these techniques is illegal and can result in severe consequences.

To learn more about privilege escalation techniques and how to defend against them, refer to the relevant resources and documentation available.
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Qap:**

* 'euid' jatlh 1000 lo'laH 'setuid' Daq, 'bash' 'ruid' (99) 'euid' qay'be' 'bash' -p vItlhutlh.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Qap**:

The **euid** (Effective User ID), **ruid** (Real User ID), and **suid** (Saved User ID) are important concepts in Linux systems that relate to user privileges and privilege escalation.

- The **euid** represents the effective user ID of a process. It determines the permissions and privileges that the process has when accessing system resources. By changing the **euid**, a process can temporarily elevate its privileges to perform certain actions that would otherwise be restricted.

- The **ruid** represents the real user ID of a process. It is the user ID that the process was initially started with and remains constant throughout its execution. The **ruid** determines the user's permissions and privileges for the duration of the process.

- The **suid** represents the saved user ID of a process. It is used to temporarily store the **euid** when switching between different user privileges. The **suid** is typically used in scenarios where a process needs to drop its privileges temporarily and then regain them later.

Understanding the relationship between these user IDs is crucial for privilege escalation techniques. By exploiting vulnerabilities or misconfigurations, an attacker can manipulate these user IDs to gain elevated privileges and perform unauthorized actions on a system.

It is important for system administrators to implement proper security measures to prevent unauthorized privilege escalation. This includes regularly updating and patching the system, configuring user permissions correctly, and monitoring for any suspicious activities that may indicate a privilege escalation attempt.

By understanding the concepts of **euid**, **ruid**, and **suid**, both attackers and defenders can better understand the mechanisms behind privilege escalation and take appropriate actions to secure their systems.
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## References
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a><strong> 'e'ghletlh</strong></summary>

* 'e' 'oH **'ay'**? 'e' 'oH **HackTricks** 'e' **company**? 'ej 'e' vItlhutlh **HackTricks** **latest version** 'ej **PEASS** **download** 'e' vItlhutlh? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **check**!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) 'e' **collection** 'ej [**NFTs**](https://opensea.io/collection/the-peass-family) 'e' **Discover**
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) 'e' **Get**
* **Join** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) 'ej [**telegram group**](https://t.me/peass) 'ej **follow** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share** 'e' **hacking tricks** 'e' **submitting PRs** 'e' [hacktricks repo](https://github.com/carlospolop/hacktricks) 'ej [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
