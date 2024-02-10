# Writable Sys Path +Dll Hijacking Privesc

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Introduction

If you found that you can **write in a System Path folder** (note that this won't work if you can write in a User Path folder) it's possible that you could **escalate privileges** in the system.

In order to do that you can abuse a **Dll Hijacking** where you are going to **hijack a library being loaded** by a service or process with **more privileges** than yours, and because that service is loading a Dll that probably doesn't even exist in the entire system, it's going to try to load it from the System Path where you can write.

For more info about **what is Dll Hijackig** check:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Privesc with Dll Hijacking

### Finding a missing Dll

The first thing you need is to **identify a process** running with **more privileges** than you that is trying to **load a Dll from the System Path** you can write in.

The problem in this cases is that probably thoses processes are already running. To find which Dlls are lacking the services you need to launch procmon as soon as possible (before processes are loaded). So, to find lacking .dlls do:

* **Create** the folder `C:\privesc_hijacking` and add the path `C:\privesc_hijacking` to **System Path env variable**. You can do this **manually** or with **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* **`procmon`** jaj **`Options`** --> **`Enable boot logging`** jaj **`OK`** jaj **`prompt`**.
* **reboot** jaj. **`procmon`** jaj **recording** jaj **events** asap jaj.
* **Windows** jaj **execute `procmon`** jaj, **running** jaj jaj **ask** jaj **store** jaj **events** jaj **file** jaj.
* **After** **file** jaj **generated**, **close** jaj **`procmon`** jaj **open** jaj **events file** jaj.
* **Add** **filters** jaj **find** Dlls jaj **proccess tried to load** jaj **writable System Path folder** jaj:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Missed Dlls

**virtual (vmware) Windows 11 machine** jaj **results** jaj:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

**.exe** jaj **ignore** jaj, **missed DLLs** jaj:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

**Finding** jaj, **interesting blog post** jaj **explains** [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll) jaj. **are going to do now** jaj.

### Exploitation

**escalate privileges** jaj **hijack** library **WptsExtensions.dll** jaj. **path** jaj **name** jaj **generate** **malicious dll** jaj.

[**try to use any of these examples**](../dll-hijacking.md#creating-and-compiling-dlls) jaj. **run payloads** jaj: get a rev shell, add a user, execute a beacon...

{% hint style="warning" %}
**not all the service are run** **`NT AUTHORITY\SYSTEM`** jaj **`NT AUTHORITY\LOCAL SERVICE`** jaj **less privileges** jaj **won't be able to create a new user** jaj **abuse its permissions**.\
**`seImpersonate`** privilege jaj, **use**[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md) jaj. **rev shell** jaj **better option** jaj **trying to create a user** jaj.
{% endhint %}

**Task Scheduler** service jaj **Nt AUTHORITY\SYSTEM** jaj.

**generated the malicious Dll** (_x64 rev shell used and shell back but defender killed it because it was from msfvenom_), **save** jaj **writable System Path** **WptsExtensions.dll** jaj **restart** jaj **computer** (or restart the service or do whatever it takes to rerun the affected service/program).

**service re-started**, **dll should be loaded and executed** (can **reuse** **procmon** trick jaj **library loaded as expected**).

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
