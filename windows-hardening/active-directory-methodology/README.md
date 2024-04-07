# Active Directory Metodolojisi

<details>

<summary><strong>A'dan Z'ye AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Temel Bakış

**Active Directory**, **ağ yöneticilerinin** ağ içinde **alanlar**, **kullanıcılar** ve **nesneleri** verimli bir şekilde oluşturmasına ve yönetmesine olanak tanıyan temel bir teknoloji olarak hizmet verir. Geniş bir kullanıcı kitlesini yönetmeyi kolaylaştıran bir şekilde ölçeklendirilmiştir, **grupları** ve **alt grupları** yönetirken çeşitli seviyelerde **erişim haklarını** kontrol eder.

**Active Directory** yapısı üç temel katmandan oluşur: **alanlar**, **ağaçlar** ve **ormanlar**. Bir **alan**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesnelerin bir koleksiyonunu kapsar. **Ağaçlar**, bu alanları birleştiren ortak bir yapıya sahip olan alanların gruplarıdır ve bir **orman**, birbirleri arasında **güven ilişkileri** ile bağlı olan birden fazla ağacın koleksiyonunu temsil eder, organizasyon yapısının en üst katmanını oluşturur. Her bir seviyede belirli **erişim** ve **iletişim hakları** belirlenebilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Dizin** – Active Directory nesneleriyle ilgili tüm bilgileri barındırır.
2. **Nesne** – Dizin içindeki varlıkları belirtir, **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** gibi.
3. **Alan** – Dizin nesneleri için bir konteyner görevi görür, her biri kendi nesne koleksiyonunu koruyan birden fazla alanın bir **orman** içinde bir arada bulunabilme yeteneğine sahiptir.
4. **Ağaç** – Ortak bir kök alanı paylaşan alanların bir gruplaması.
5. **Orman** – Active Directory'deki organizasyon yapısının zirvesi, birbirleri arasında **güven ilişkileri** olan birkaç ağacın koleksiyonundan oluşur.

**Active Directory Domain Hizmetleri (AD DS)**, ağ içinde merkezi yönetim ve iletişim için kritik olan bir dizi hizmeti kapsar. Bu hizmetler şunları içerir:

1. **Alan Hizmetleri** – Veri depolamayı merkezileştirir ve **kullanıcılar** ve **alanlar** arasındaki etkileşimleri yönetir, **kimlik doğrulama** ve **arama** işlevlerini içerir.
2. **Sertifika Hizmetleri** – Güvenli **dijital sertifikaların** oluşturulmasını, dağıtımını ve yönetimini denetler.
3. **Hafif Dizin Hizmetleri** – **LDAP protokolü** aracılığıyla dizin tabanlı uygulamaları destekler.
4. **Dizin Federasyon Hizmetleri** – Birden fazla web uygulamasında kullanıcıları **tek oturum açma** yetenekleriyle kimlik doğrular.
5. **Hak Yönetimi** – Telif hakkı materyallerini koruyarak izinsiz dağıtımını ve kullanımını düzenlemeye yardımcı olur.
6. **DNS Hizmeti** – **Alan adlarının** çözümlemesi için hayati öneme sahiptir.

Daha detaylı bir açıklama için: [**TechTerms - Active Directory Tanımı**](https://techterms.com/definition/active\_directory)

### **Kerberos Kimlik Doğrulaması**

Bir **AD'yi saldırmayı** öğrenmek için **Kerberos kimlik doğrulama sürecini** gerçekten iyi anlamanız gerekir.\
[Hala nasıl çalıştığını bilmiyorsanız bu sayfayı okuyun.](kerberos-authentication.md)

## Kopya Kağıt

Bir AD'yi sıralamak/çıkarmak için hangi komutları çalıştırabileceğinizi hızlıca görmek için [https://wadcoms.github.io/](https://wadcoms.github.io) adresine gidebilirsiniz.

## Keşif Active Directory (Kimlik bilgileri/oturumlar olmadan)

Eğer sadece bir AD ortamına erişiminiz var ancak herhangi bir kimlik bilgisi/oturumunuz yoksa şunları yapabilirsiniz:

* **Ağı pentest edin:**
* Ağı taramak, makineleri bulmak ve açık portları açmak ve bunlardan **zafiyetleri sömürmek** veya **kimlik bilgilerini çıkarmak** için denemelerde bulunmak (örneğin, [yazıcılar çok ilginç hedefler olabilir](ad-information-in-printers.md).
* DNS'yi sıralamak, alan içindeki ana sunucular hakkında bilgi verebilir, web, yazıcılar, paylaşımlar, vpn, medya vb.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Daha fazla bilgi için Genel [**Pentest Metodolojisi**](../../generic-methodologies-and-resources/pentesting-methodology.md)'ne bakın.
* **Smb hizmetlerinde null ve Guest erişimini kontrol edin** (bu modern Windows sürümlerinde çalışmayabilir):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Bir SMB sunucusunu nasıl sıralayacağınıza dair daha detaylı bir kılavuz burada bulunabilir:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Ldap'ı sıralayın**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* LDAP'ı nasıl sıralayacağınıza dair daha detaylı bir kılavuz burada bulunabilir (özellikle **anonim erişime** dikkat edin):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Ağı zehirleyin**
* [**Responder ile hizmetleri taklit ederek kimlik bilgileri toplayın**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* [**Röle saldırısını kötüye kullanarak ana bilgisayara erişin**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* [**Evil-S ile sahte UPnP hizmetlerini ortaya çıkararak kimlik bilgilerini toplayın**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* İç belgelerden, sosyal medyadan, alan ortamlarındaki (genellikle web) hizmetlerden ve genel olarak erişilebilir yerlerden kullanıcı adlarını/isimleri çıkarın.
* Şirket çalışanlarının tam adlarını bulursanız, farklı AD **kullanıcı adı kurallarını deneyebilirsiniz (**[**bunu okuyun**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın kurallar şunlardır: _AdSoyad_, _Ad.Soyad_, _NamSur_ (her biri 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SoyadAd_, _Soyad.Ad_, _SoyadN_, _Soyad.N_, 3 _rastgele harf ve 3 rastgele sayı_ (abc123).
* Araçlar:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)
### Kullanıcı numaralandırma

* **Anonim SMB/LDAP numaralandırma:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarını kontrol edin.
* **Kerbrute numaralandırma**: Bir **geçersiz kullanıcı adı istendiğinde** sunucu, **Kerberos hata** kodu _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_ kullanarak yanıt verecektir, böylece kullanıcı adının geçersiz olduğunu belirleyebiliriz. **Geçerli kullanıcı adları**, ya **AS-REP içinde TGT** yanıtını ya da _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_ hatasını alacaktır, bu da kullanıcının ön kimlik doğrulamasını gerçekleştirmesi gerektiğini gösterir.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) Sunucusu**

Eğer ağda bu sunuculardan birini bulursanız, ayrıca buna karşı **kullanıcı numaralandırması yapabilirsiniz**. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
[**Bu github deposunda**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bu ([**istatistiksel-olası-kullanıcı-adları**](https://github.com/insidetrust/statistically-likely-usernames)) listelerini kullanıcı adları bulabilirsiniz.

Ancak, bu adımdan önce gerçekleştirmeniz gereken keşif adımından **şirkette çalışan kişilerin adını** bilmelisiniz. Ad ve soyadı ile [**namemash.py**](https://gist.github.com/superkojiman/11076951) betiğini kullanarak potansiyel geçerli kullanıcı adları oluşturabilirsiniz.
{% endhint %}

### Bir veya birkaç kullanıcı adını bilmek

Tamam, zaten geçerli bir kullanıcı adınız olduğunu biliyorsunuz ama şifreleriniz yok... O zaman şunları deneyin:

* [**ASREPRoast**](asreproast.md): Bir kullanıcının _DONT\_REQ\_PREAUTH_ özniteliğine sahip **olmadığını** biliyorsanız, o kullanıcı için bir AS\_REP mesajı **isteyebilirsiniz**. Bu mesaj, kullanıcının şifresinin türetilmiş bir sürümü tarafından şifrelenmiş bazı veriler içerecektir.
* [**Şifre Sıçratma**](password-spraying.md): Keşfettiğiniz kullanıcılarla en **sık kullanılan şifreleri** deneyin, belki bazı kullanıcılar kötü bir şifre kullanıyordur (şifre politikasını göz önünde bulundurun!).
* Ayrıca, kullanıcıların posta sunucularına erişmeye çalışmak için **OWA sunucularına sıçrama** yapabilirsiniz.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Zehirlenmesi

Ağın bazı protokollerini zehirleyerek **bazı meydan okuma karmalarını** kırabilirsiniz:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Aktarımı

Etkin dizini numaralandırmayı başardıysanız, **daha fazla e-posta ve ağın daha iyi anlayışına sahip olacaksınız**. AD ortamına erişim elde etmek için NTML [**aktarım saldırıları**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) yapabilirsiniz.

### NTLM Kimlik Bilgilerini Çalma

**Diğer PC'lere veya paylaşımlara erişebiliyorsanız** (boş veya misafir kullanıcı ile) dosyalar yerleştirebilirsiniz (örneğin bir SCF dosyası) ki bu dosyalara bir şekilde erişildiğinde sizinle karşılaştırılan bir NTML kimlik doğrulamasını tetikleyecektir, böylece kimlik doğrulamasını **çalabilirsiniz** ve kırabilirsiniz:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Kimlik Bilgileri/Oturum ile Etkin Dizin Numaralandırma

Bu aşamada **geçerli bir etki alanı hesabının kimlik bilgilerini veya oturumunu ele geçirmiş olmanız gerekmektedir.** Geçerli kimlik bilgileriniz veya bir etki alanı kullanıcısı olarak kabuk aldıysanız, **önce verilen seçeneklerin hala diğer kullanıcıları tehlikeye atma seçenekleri olduğunu hatırlamalısınız**.

Kimlik doğrulamalı numaralandırmaya başlamadan önce **Kerberos çift atlama sorununu** bilmelisiniz.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Numaralandırma

Bir hesabı ele geçirmek, **tüm etki alanını tehlikeye atmak için büyük bir adımdır**, çünkü **Etkin Dizin Numaralandırmasına başlayabileceksiniz:**

[**ASREPRoast**](asreproast.md) ile şimdi her olası savunmasız kullanıcıyı bulabilirsiniz ve [**Şifre Sıçratma**](password-spraying.md) ile **tüm kullanıcı adlarının listesini** alabilir ve ele geçirilen hesabın şifresini, boş şifreleri ve yeni umut verici şifreleri deneyebilirsiniz.

* [**Temel bir keşif yapmak için CMD'yi kullanabilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
* [**Keşif için powershell kullanabilirsiniz**](../basic-powershell-for-pentesters/), bu daha gizli olacaktır
* [**Powerview'i kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md) daha detaylı bilgiler çıkarmak için
* Etkin dizinde keşif için harika bir araç olan [**BloodHound**](bloodhound.md) bulunmaktadır. **Çok gizli olmayabilir** (kullandığınız toplama yöntemlerine bağlı olarak), ama **eğer umursamıyorsanız** kesinlikle denemelisiniz. Kullanıcıların nereden RDP yapabileceğini bulun, diğer gruplara giden yolları bulun, vb.
* **Diğer otomatik AD numaralandırma araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**AD'nin DNS kayıtları**](ad-dns-records.md) ilginç bilgiler içerebilir.
* **GUI'ye sahip bir araç** olan **SysInternal** Suite'ten **AdExplorer.exe** kullanarak dizini numaralandırabilirsiniz.
* _userPassword_ ve _unixUserPassword_ alanlarında kimlik bilgilerini aramak için **ldapsearch** kullanarak LDAP veritabanında arama yapabilirsiniz. Diğer yöntemler için bkz. [PayloadsAllTheThings'teki AD Kullanıcı yorumunda şifre](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
* **Linux** kullanıyorsanız, [**pywerview**](https://github.com/the-useless-one/pywerview) kullanarak etki alanını numaralandırabilirsiniz.
* Otomatik araçları da deneyebilirsiniz:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Tüm etki alanı kullanıcılarını çıkarma**

Windows'tan tüm etki alanı kullanıcı adlarını elde etmek çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta ise şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Numaralandırma bölümü küçük görünse de bu en önemli kısımdır. Bağlantılara erişin (özellikle cmd, powershell, powerview ve BloodHound'un bağlantısına), bir etki alanını nasıl numaralandıracağınızı öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir değerlendirme sırasında, bu, DA yolunu bulmanız veya hiçbir şey yapılamayacağına karar vermeniz için ana an olacaktır.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetler tarafından kullanılan **TGS biletlerini** elde etmeyi ve şifrelerine dayanan şifreleme yöntemlerini **çevrimdışı olarak** kırmayı içerir.

Daha fazlası için:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}
### Uzak bağlantı (RDP, SSH, FTP, Win-RM, vb.)

Birkaç kimlik bilgisine sahip olduktan sonra herhangi bir **makineye erişiminizin olup olmadığını** kontrol edebilirsiniz. Bu konuda, farklı protokollerle birkaç sunucuya bağlanmayı denemek için **CrackMapExec** kullanabilirsiniz, taramalarınıza göre uygun şekilde.

### Yerel Yetki Yükseltme

Eğer ele geçirdiğiniz kimlik bilgileri veya düzenli bir etki alanı kullanıcısı olarak bir oturumunuz varsa ve bu kullanıcıyla etki alanındaki **herhangi bir makineye erişiminiz varsa**, yerel olarak **yetkileri yükseltmeye ve kimlik bilgilerini ele geçirmeye** çalışmalısınız. Bu, çünkü yalnızca yerel yönetici yetkilerine sahip olduğunuzda diğer kullanıcıların bellekteki (LSASS) ve yereldeki (SAM) hash'lerini **dökme** yeteneğine sahip olacaksınız.

Bu kitapta [**Windows'ta yerel yetki yükseltme**](../windows-local-privilege-escalation/) hakkında tam bir sayfa ve bir [**kontrol listesi**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Geçerli Oturum Biletleri

Çok **olasılıksız** olsa da, mevcut kullanıcıda **beklenmeyen kaynaklara erişim izni veren biletler** bulabileceğinizi kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Aktarımı

Eğer etkin dizini numaralandırmayı başardıysanız, **daha fazla e-posta ve ağın daha iyi anlayışına sahip olacaksınız**. NTML [**aktarım saldırılarını**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** zorlayabilirsiniz**.

### Bilgisayar Paylaşımlarında Kimlik Bilgilerini Arayın

Temel kimlik bilgileriniz olduğuna göre, AD içinde **paylaşılan ilginç dosyaları bulup bulamayacağınızı kontrol etmelisiniz**. Bu işlemi manuel olarak yapabilirsiniz ancak çok sıkıcı ve tekrarlayan bir görevdir (ve yüzlerce belge bulursanız kontrol etmeniz gerekebilir).

[**Bu bağlantıyı takip ederek kullanabileceğiniz araçlar hakkında bilgi edinin.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### NTLM Kimlik Bilgilerini Çalma

**Diğer PC'lere veya paylaşımlara erişebiliyorsanız**, (örneğin bir SCF dosyası gibi) **erişildiğinde size karşı bir NTML kimlik doğrulaması tetikleyecek dosyalar yerleştirebilirsiniz** böylece **NTLM meydan okumasını çözmek için çalabilirsiniz**:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu zafiyet, **herhangi bir kimliği doğrulanmış kullanıcının etki alanı denetleyicisini tehlikeye atmasına izin verdi**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Ayrıcalıklı Kimlik Bilgileri/Oturum ile Etkin Dizin Üzerinde Ayrıcalık Yükseltme

**Aşağıdaki teknikler için düzenli bir etki alanı kullanıcısı yeterli değil, bu saldırıları gerçekleştirmek için özel ayrıcalıklara/kimlik bilgilerine ihtiyacınız var.**

### Hash Çıkarma

Umarım [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) dahil olmak üzere bazı yerel yönetici hesaplarını **tehlikeye atmayı başarmışsınızdır**.\
Sonra, bellekte ve yerel olarak tüm hash'leri dökmek için zamanı gelmiştir.\
[**Farklı hash'leri elde etmenin farklı yolları hakkında bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Hash Geçişi

**Bir kullanıcının hash'ine sahip olduktan sonra**, onu **taklit etmek** için kullanabilirsiniz.\
Bu hash'i kullanarak NTLM kimlik doğrulamasını gerçekleştirecek bir **aracı kullanmanız gerekmektedir**, **veya** yeni bir **oturum açma** oluşturabilir ve bu **hash'i LSASS içine enjekte edebilirsiniz**, böylece herhangi bir **NTLM kimlik doğrulaması gerçekleştirildiğinde**, bu **hash kullanılacaktır**. Son seçenek, mimikatz'ın yaptığı işlemdir.\
[Daha fazla bilgi için **bu sayfayı okuyun.**](../ntlm/#pass-the-hash)

### Hash Üzerinden Geçiş/Anahtarı Geçiş

Bu saldırı, kullanıcı NTLM hash'ini istemek için Kerberos biletleri talep etmeyi amaçlar ve yaygın Pass The Hash üzerinden NTLM protokolüne alternatif bir yöntemdir. Bu nedenle, bu özellikle **NTLM protokolünün devre dışı bırakıldığı ve yalnızca Kerberos'un izin verildiği ağlarda** kullanışlı olabilir.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Bilet Geçişi

**Bilet Geçişi (PTT)** saldırı yönteminde, saldırganlar bir kullanıcının şifresi veya hash değerleri yerine **kimlik doğrulama bileti çalarlar**. Bu çalınan bilet daha sonra kullanılarak kullanıcı taklit edilir ve ağ içindeki kaynaklara ve hizmetlere izinsiz erişim sağlanır.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Kimlik Bilgilerinin Tekrar Kullanımı

Eğer bir **yerel yönetici**nin **hash'ine veya şifresine** sahipseniz, bunu kullanarak başka **PC'lere yerel olarak giriş yapmayı denemelisiniz**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Bu oldukça **gürültülü** ve **LAPS** bunu **hafifletebilir**.
{% endhint %}

### MSSQL Kötüye Kullanımı ve Güvenilir Bağlantılar

Bir kullanıcının **MSSQL örneklerine erişim** ayrıcalıkları varsa, bunu kullanarak MSSQL ana bilgisayarında (SA olarak çalışıyorsa) **komutları yürütebilir**, NetNTLM **hash'ini çalabilir** veya hatta bir **röle** **saldırısı** gerçekleştirebilir.\
Ayrıca, bir MSSQL örneği başka bir MSSQL örneği tarafından güvenilir olarak kabul ediliyorsa (veritabanı bağlantısı). Kullanıcı, güvenilen veritabanı üzerinde ayrıcalıklara sahipse, güven ilişkisini kullanarak diğer örnekte de sorguları yürütebilecektir. Bu güvenler zincirlenebilir ve kullanıcı bir noktada yanlış yapılandırılmış bir veritabanı bulabilir ve burada komutları yürütebilir.\
**Veritabanları arasındaki bağlantılar orman güvenleri dahil çalışır.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Kısıtlanmamış Delege

Eğer [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) özniteliğine sahip bir Bilgisayar nesnesi bulursanız ve bilgisayarda etki alanı ayrıcalıklarınız varsa, bilgisayara giriş yapan her kullanıcının belleğinden TGT'leri dökme yeteneğine sahip olacaksınız.\
Bu nedenle, bir **Etki Alanı Yöneticisi bilgisayara giriş yaptığında**, onun TGT'sini dökebilecek ve [Bilet Taşıma](pass-the-ticket.md) kullanarak onun yerine geçebileceksiniz.\
Kısıtlanmış delege sayesinde hatta bir Yazıcı Sunucusunu bile **otomatik olarak tehlikeye atabilirsiniz** (umarım bir DC olmaz).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Kısıtlanmış Delege

Bir kullanıcı veya bilgisayar "Kısıtlanmış Delege" için izin verilirse, bir bilgisayarda bazı hizmetlere erişmek için **herhangi bir kullanıcıyı taklit edebilecektir**.\
Sonra, bu kullanıcı/bilgisayarın **hash'ini ele geçirirseniz**, bazı hizmetlere erişmek için (hatta etki alanı yöneticileri dahil) **herhangi bir kullanıcıyı taklit edebileceksiniz**.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Kaynak Tabanlı Kısıtlı Delege Kötüye Kullanımı

Uzaktaki bir bilgisayarın Active Directory nesnesinde **YAZMA** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla kod yürütme** imkanı sağlar:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL Kötüye Kullanımı

Kompromize edilmiş kullanıcı, bazı **etki alanı nesneleri üzerinde ilginç ayrıcalıklara** sahip olabilir ve bu da size **yan yana hareket etme**/**ayrıcalıkları yükseltme** imkanı verebilir.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Yazıcı Kuyruğu hizmeti kötüye kullanımı

Etki alanında dinleyen bir **Kuyruk hizmeti keşfetmek**, yeni kimlik bilgileri **edinmek** ve **ayrıcalıkları yükseltmek** için **kötüye kullanılabilir**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Üçüncü taraf oturumları kötüye kullanımı

**Diğer kullanıcılar** **kompromize edilen** makineye **erişirse**, bellekten kimlik bilgilerini **toplamak** ve hatta süreçlerine **beacon enjekte etmek** için kullanılabilir.\
Genellikle kullanıcılar sisteme RDP aracılığıyla erişir, bu yüzden üçüncü taraf RDP oturumları üzerinde birkaç saldırıyı nasıl gerçekleştireceğinizi burada bulabilirsiniz:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Yönetici şifresini yönetmek için bir sistem** sağlar, bu şifrenin **rastgele**, benzersiz ve sık sık **değiştirildiğinden** emin olur. Bu şifreler Active Directory'de depolanır ve erişim sadece yetkili kullanıcılara ACL'ler aracılığıyla kontrol edilir. Bu şifrelere erişim için yeterli izinlerle, diğer bilgisayarlara geçiş yapmak mümkün olur.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Sertifika Hırsızlığı

Kompromize edilen makineden **sertifikaları toplamak**, çevrede ayrıcalıkları **yükseltmek** için bir yol olabilir:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Sertifika Şablonları Kötüye Kullanımı

Eğer **savunmasız şablonlar** yapılandırılmışsa, bunları kötüye kullanarak ayrıcalıkları yükseltebilirsiniz:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Yüksek ayrıcalıklı hesapla son aşama saldırı

### Etki Alanı Kimlik Bilgilerini Dökmek

Bir kez **Etki Alanı Yöneticisi** veya daha iyi **Kurumsal Yönetici** ayrıcalıklarına sahip olduğunuzda, **etki alanı veritabanını** _ntds.dit_ **dökebilirsiniz**.

[**DCSync saldırısı hakkında daha fazla bilgi burada bulunabilir**](dcsync.md).

[**NTDS.dit'yi nasıl çalacağınız hakkında daha fazla bilgi burada bulunabilir**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Ayrıcalıkları Yükseltme Olarak Kalıcılık

Önceki tartışılan bazı teknikler kalıcılık için kullanılabilir.\
Örneğin:

*   Kullanıcıları [**Kerberoast**](kerberoast.md) saldırısına karşı savunmasız hale getirebilirsiniz

```powershell
Set-DomainObject -Identity <kullanıcıadı> -Set @{serviceprincipalname="sahte/HİÇBİRŞEY"}r
```
*   Kullanıcıları [**ASREPRoast**](asreproast.md) saldırısına karşı savunmasız hale getirebilirsiniz

```powershell
Set-DomainObject -Identity <kullanıcıadı> -XOR @{UserAccountControl=4194304}
```
*   Bir kullanıcıya [**DCSync**](./#dcsync) ayrıcalıklarını verin

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=ALT,DC=ETKİALANI,DC=YEREL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Gümüş Bilet

**Gümüş Bilet saldırısı**, belirli bir hizmet için **meşru Bilet Verme Hizmeti (TGS) bileti** oluşturmak için **NTLM hash'ini** (örneğin, **PC hesabının hash'ini**) kullanır. Bu yöntem, hizmet ayrıcalıklarına **erişmek** için kullanılır.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Altın Bilet

**Altın Bilet saldırısı**, bir saldırganın Active Directory (AD) ortamında **krbtgt hesabının NTLM hash'ine erişmesini** içerir. Bu hesap, AD ağı içinde **kimlik doğrulama yapmak için esas olan** **Bilet Verme Biletleri (TGT'ler)** tümünü imzalamak için kullanılır.

Saldırgan bu hash'i elde ettikten sonra istediği hesaplar için **TGT'ler** oluşturabilir (Gümüş bilet saldırısı).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Elmas Bilet

Bunlar, **ortak altın bilet algılama mekanizmalarını atlayan** altın biletler gibi dövülmüş altın biletlerdir.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}
### **Sertifikalar Hesap Kalıcılığı**

**Bir hesabın sertifikalarına sahip olmak veya onları isteyebilmek**, kullanıcının hesabında kalıcı olabilmek için çok iyi bir yoldur (şifresini değiştirse bile):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Sertifikalar Alan Kalıcılığı**

**Sertifikaları kullanarak, etki alanı içinde yüksek ayrıcalıklarla kalıcı olmak da mümkündür:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder Grubu

Active Directory'deki **AdminSDHolder** nesnesi, **Domain Admins** ve **Enterprise Admins** gibi **özel grupların** güvenliğini sağlayarak yetkisiz değişiklikleri önlemek için bu gruplara standart bir **Erişim Kontrol Listesi (ACL)** uygular. Ancak, bu özellik istismar edilebilir; bir saldırgan, AdminSDHolder'ın ACL'sini değiştirerek düzenli bir kullanıcıya tam erişim verirse, bu kullanıcı tüm özel gruplar üzerinde geniş kontrol elde eder. Bu koruma önlemi, korumak amacıyla tasarlanmış olsa da, yakından izlenmediği sürece izinsiz erişime izin verebilir.

[**AdminDSHolder Grubu hakkında daha fazla bilgi burada.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Kimlik Bilgileri

Her **Domain Controller (DC)** içinde bir **yerel yönetici** hesabı bulunmaktadır. Bu tür bir makinede yönetici hakları elde edilerek, yerel Yönetici hash'i **mimikatz** kullanılarak çıkarılabilir. Bunun ardından, bu şifrenin kullanımını **etkinleştirmek için bir kayıt değişikliği** gereklidir, bu da uzaktan Yönetici hesabına erişim sağlar.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL Kalıcılığı

Gelecekte **ayrıcalıkları yükseltmesine izin verecek** belirli etki alanı nesneleri üzerinde bir **kullanıcıya** bazı **özel izinler verebilirsiniz**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Güvenlik Tanımlayıcıları

**Güvenlik tanımlayıcıları**, bir **nesnenin** üzerinde **sahip olduğu izinleri saklamak** için kullanılır. Bir nesnenin güvenlik tanımlayıcısında **küçük bir değişiklik yaparak**, bir ayrıcalıklı gruba üye olmadan o nesne üzerinde çok ilginç ayrıcalıklar elde edebilirsiniz.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### İskelet Anahtar

**LSASS**'ı bellekte değiştirerek, tüm etki alanı hesaplarına erişim sağlayan **evrensel bir şifre** oluşturun.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Özel SSP

[SSP'nin (Güvenlik Destek Sağlayıcısı) ne olduğunu buradan öğrenin.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
**Kendi SSP'nizi** oluşturarak, makineye erişim için kullanılan **kimlik bilgilerini düz metin olarak yakalayabilirsiniz**.

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

AD'de yeni bir **Domain Controller** kaydeder ve belirli nesneler üzerinde (SIDHistory, SPN'ler...) **modifikasyonlarla** hiçbir **log bırakmadan** bu nesneleri **itme** işlemi yapar. **DA ayrıcalıklarına** ve **kök etki alanı** içinde olmanıza gerek vardır.\
Yanlış veri kullanırsanız, oldukça çirkin loglar ortaya çıkacaktır.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS Kalıcılığı

Daha önce, **LAPS şifrelerini okuma izniniz varsa** ayrıcalıkları nasıl yükselteceğimizi tartıştık. Ancak, bu şifreler aynı zamanda **kalıcılığı sürdürmek** için de kullanılabilir.\
Kontrol edin:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Orman Ayrıcalık Yükseltme - Etki Alanı Güveni

Microsoft, **Ormanı** güvenlik sınırı olarak görür. Bu, **tek bir etki alanının tehlikeye atılması, tüm Ormanın tehlikeye atılmasına yol açabileceği anlamına gelir**.

### Temel Bilgiler

Bir [**etki alanı güveni**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx), bir **etki alanından** başka bir **etki alanındaki** kaynaklara erişimi sağlayan bir güvenlik mekanizmasıdır. Temelde, iki etki alanının kimlik doğrulama sistemlerini birbirine bağlar ve kimlik doğrulama doğrulamalarının sorunsuz bir şekilde akmasına izin verir. Etki alanları bir güvenlik ilişkisi kurduğunda, **Domain Controller'ları (DC'ler)** arasında belirli **anahtarları** değiştirir ve saklarlar, bu da güvenin bütünlüğü için önemlidir.

Tipik bir senaryoda, bir kullanıcı **güvenilen bir etki alanındaki** bir hizmete erişmek istiyorsa, önce kendi etki alanının DC'sinden bir **inter-realm TGT** olarak bilinen özel bir bilet talep etmelidir. Bu TGT, her iki etki alanının da anlaştığı bir ortak **anahtarla** şifrelenmiştir. Kullanıcı daha sonra bu TGT'yi **güvenilen etki alanının DC'sine** sunarak bir hizmet bileti (**TGS**) alır. Güvenilen etki alanının DC'si, güvenilen etki alanının DC'si tarafından inter-realm TGT'yi doğruladığında, kullanıcıya hizmete erişim sağlayan bir TGS verir.

**Adımlar**:

1. **Etki Alanı 1**'deki bir **istemci bilgisayar**, **NTLM hash'ini** kullanarak kendi **Domain Controller'ından (DC1)** bir **Bilet Verme Bileti (TGT)** talep ederek işlemi başlatır.
2. DC1, istemcinin başarılı bir şekilde kimlik doğrulandığı durumda yeni bir TGT verir.
3. İstemci daha sonra, **Etki Alanı 2'deki** kaynaklara erişmek için gereken bir **inter-realm TGT** talep eder.
4. Inter-realm TGT, iki yönlü etki alanı güveninin bir parçası olarak DC1 ve DC2 arasında paylaşılan bir **güven anahtarı** ile şifrelenir.
5. İstemci, inter-realm TGT'yi **Etki Alanı 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, inter-realm TGT'yi paylaşılan güven anahtarı ile doğrular ve geçerliyse, istemcinin erişmek istediği Etki Alanı 2'deki sunucu için bir **Hizmet Bilet Servisi (TGS)** verir.
7. Son olarak, istemci bu TGS'yi sunucuya sunar, bu da sunucunun hesap hash'i ile şifrelenmiştir ve Etki Alanı 2'deki hizmete erişim sağlar.

### Farklı güvenler

**Bir güvenin 1 yönlü veya 2 yönlü olabileceğini** fark etmek önemlidir. 2 yönlü seçeneklerde, her iki etki alanı da birbirine güvenir, ancak **1 yönlü** güven ilişkisinde etki alanlarından biri **güvenilen** diğeri ise **güvenen** etki alanı olacaktır. Bu durumda, **güvenilen etki alanından güvenen etki alanındaki kaynaklara erişebileceksiniz**.

Eğer Domain A, Domain B'ye güvenirse, A güvenen etki alanı olurken B güvenilen etki alanı olur. Ayrıca, **Domain A**'da bu bir **Dışa Doğru güven** olacaktır; ve **Domain B**'de bu bir **İçe Doğru güven** olacaktır.

**Farklı güven ilişkileri**

* **Ebeveyn-Çocuk Güvenleri**: Bu, aynı ormanda yaygın bir kurulumdur, burada bir alt etki alanının otomatik olarak ana etki alanıyla iki yönlü geçişli bir güven ilişkisi vardır. Temelde, bu, kimlik doğrulama isteklerinin ana ve çocuk arasında sorunsuz bir şekilde akmasını sağlar.
* **Çapraz Bağlantı Güvenleri**: "kısayol güvenleri" olarak adlandırılan bu güvenler, yönlendirme süreçlerini hızlandırmak için çocuk etki alanları arasında kurulur. Karmaşık ormanlarda, kimlik doğrulama yönlendirmelerinin genellikle orman köküne kadar yükselmesi ve ardından hedef etki alana kadar inmesi gerekir. Çapraz bağlantılar oluşturarak, yol kısaltılır, bu da coğrafi olarak dağılmış ortamlarda özellikle faydalıdır.
* **Dış Güvenler**: Bu, farklı, ilişkisiz etki alanları arasında kurulur ve doğası gereği geçişli değildir. [Microsoft belgelerine](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx) göre, dış güvenler, mevcut ormanla bağlı olmayan bir etki alanındaki kaynaklara erişmek için kullanışlıdır. Dış güvenlerle SID filtreleme ile güvenlik artırılır.
* **Ağaç-Kök Güvenleri**: Bu güvenler, orman kök etki alanı ile yeni eklenen bir ağaç kökü arasında otomatik olarak kurulur. Sık karşılaşılmayan ağaç-kök güvenleri, yeni etki alanı ağaçlarını bir ormana eklemek için önemlidir, onlara benzersiz bir etki alanı adı koruma ve iki yönlü geçişliliği sağlama imkanı verir. Daha fazla bilgiye [Microsoft'un rehberinde](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx) bulunabilir.
* **Orman Güvenleri**: Bu tür bir güven, iki orman kök etki alanı arasında iki yönlü geçişli bir güven ilişkisidir, ayrıca güvenliği artırmak için SID filtreleme uygular.
* **MIT Güvenleri**: Bu güvenler, Windows dışı, [RFC4120 uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos etki alanları ile kurulur. MIT güvenleri biraz daha özelleşmiştir ve Windows ekosistemi dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlara hizmet eder.
#### Diğer farklılıklar **güvenen ilişkilerde**

* Bir güven ilişkisi aynı zamanda **geçişli** (A B'ye güvenir, B C'ye güvenir, o zaman A C'ye güvenir) veya **geçişsiz** olabilir.
* Bir güven ilişkisi **çift yönlü güven** (her ikisi de birbirine güvenir) olarak veya **tek yönlü güven** (sadece biri diğerine güvenir) olarak kurulabilir.

### Saldırı Yolu

1. Güvenen ilişkileri **sırala**
2. Herhangi bir **güvenlik prensibi**nin (kullanıcı/grup/bilgisayar) **diğer etki alanının** kaynaklarına **erişimi** olup olmadığını kontrol et, belki ACE girişleri veya diğer etki alanının gruplarında bulunarak. **Etki alanları arasındaki ilişkilere** bak (muhtemelen bu güven ilişkisi bunun için oluşturuldu).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. **Hesapları** **kompromize** et, bu hesaplar aracılığıyla **geçiş** yapabilirsin.

Saldırganlar başka bir etki alanındaki kaynaklara üç temel mekanizma aracılığıyla erişebilir:

* **Yerel Grup Üyeliği**: Prensipler, bir sunucudaki "Yöneticiler" grubu gibi makinelerdeki yerel gruplara eklenmiş olabilir, bu da onlara o makine üzerinde önemli bir kontrol sağlar.
* **Yabancı Etki Alanı Grup Üyeliği**: Prensipler ayrıca yabancı etki alanındaki grup üyeleri de olabilir. Ancak, bu yöntemin etkinliği güvenin doğası ve grup kapsamına bağlıdır.
* **Erişim Kontrol Listeleri (ACL'ler)**: Prensipler, özellikle bir **DACL** içindeki **ACE'ler** olarak var olan **ACL'lerde** belirtilebilir, bu da onlara belirli kaynaklara erişim sağlar. ACL'lerin, DACL'lerin ve ACE'lerin mekaniği hakkında daha derinlemesine bilgi edinmek isteyenler için, "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)" adlı whitepaper çok değerli bir kaynaktır.

### Çocuktan Ebeveyn orman ayrıcalığı yükseltme
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
**2 güvenilir anahtar** bulunmaktadır, biri _Çocuk --> Ebeveyn_ için diğeri ise _Ebeveyn_ --> _Çocuk_ için.\
Mevcut alan tarafından kullanılanı şu şekilde bulabilirsiniz:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

Çocuk/ana etki alanına güveni istismar ederek Enterprise yönetici olarak yükselin ve SID-History enjeksiyonunu kullanın:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Yazılabilir Yapılandırma NC'sini Sömürme

Yapılandırma Adlandırma Bağlamının (NC) nasıl sömürülebileceğini anlamak önemlidir. Yapılandırma NC, Active Directory (AD) ortamlarındaki orman genelinde yapılandırma verileri için merkezi bir depo olarak hizmet eder. Bu veriler, ormandaki her Etki Alanı Denetleyicisine (DC) replike edilir ve yazılabilir DC'ler, Yapılandırma NC'nin yazılabilir bir kopyasını korur. Bunu sömürmek için, tercihen bir çocuk DC üzerinde **BIR SISTEM ayrıcalıklarına** sahip olmak gerekir.

**GPO'yu kök DC sitesine bağlama**

Yapılandırma NC'nin Siteler konteyneri, AD ormanı içindeki tüm etki alanına katılmış bilgisayarların siteleri hakkında bilgi içerir. Herhangi bir DC üzerinde SISTEM ayrıcalıklarıyla çalışarak, saldırganlar GPO'ları kök DC sitelerine bağlayabilir. Bu eylem, bu sitelere uygulanan politikaları manipüle ederek kök etki alanını potansiyel olarak tehlikeye atabilir.

Detaylı bilgi için [SID Filtreleme Atlatma](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) üzerine yapılan araştırmaları inceleyebilirsiniz.

**Ormandaki herhangi bir gMSA'yı tehlikeye atma**

Bir saldırı vektörü, etki alanı içindeki ayrıcalıklı gMSA'ları hedef almaktadır. gMSA'ların şifrelerini hesaplamak için gerekli olan KDS Kök anahtarı, Yapılandırma NC içinde saklanır. Herhangi bir DC üzerinde SISTEM ayrıcalıklarıyla, KDS Kök anahtarına erişmek ve ormandaki herhangi bir gMSA için şifreleri hesaplamak mümkündür.

Detaylı analiz, [Alt Etki Alanından Üst Etki Alanına Altın gMSA Güven Saldırıları](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent) üzerinde bulunabilir.

**Şema değişikliği saldırısı**

Bu yöntem sabır gerektirir, yeni ayrıcalıklı AD nesnelerinin oluşturulmasını bekler. SISTEM ayrıcalıklarıyla, bir saldırgan AD Şemasını değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verme yeteneğine sahip olabilir. Bu, yetkisiz erişime ve yeni oluşturulan AD nesneleri üzerinde kontrol sağlamaya yol açabilir.

Daha fazla okuma için [Şema Değişikliği Güven Saldırıları](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) mevcuttur.

**DA'dan EA'ya ADCS ESC5 ile**

ADCS ESC5 zafiyeti, Genel Anahtar Altyapısı (PKI) nesneleri üzerinde kontrol sağlamayı hedefler ve ormandaki herhangi bir kullanıcı olarak kimlik doğrulamasını mümkün kılan bir sertifika şablonu oluşturur. PKI nesneleri, Yapılandırma NC içinde bulunduğundan, yazılabilir bir çocuk DC'nin tehlikeye atılması ESC5 saldırılarının gerçekleştirilmesine olanak tanır.

Bu konuda daha fazla detay, [DA'dan EA'ya ESC5 ile](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) okunabilir. ADCS olmayan senaryolarda, saldırgan gerekli bileşenleri kurma yeteneğine sahiptir, [Çocuk Etki Alanı Yöneticilerinden Üst Etki Alan Yöneticilerine Yükselme](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) konusunda tartışıldığı gibi. 

### Harici Orman Etki Alanı - Tek Yönlü (Gelen) veya çift yönlü
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Bu senaryoda **alanınızın**, dış bir alan tarafından **belirsiz izinlerle güvenildiği** varsayılmaktadır. **Alanınızın hangi prensiplerinin dış alan üzerinde hangi erişime sahip olduğunu** bulmanız ve ardından bunu istismar etmeye çalışmanız gerekecektir:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Dış Orman Alanı - Tek Yönlü (Dışa Doğru)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Bu senaryoda **alanınız**, **farklı alanlardan** bir **özne**ye bazı **yetkileri güveniyor**.

Ancak, güvenen alan tarafından güvenilen alanın **öngörülebilir bir ad kullanarak** ve güvenilen şifreyi kullanarak bir kullanıcı oluşturduğu durumda, güvenilen alana **erişmek mümkün olabilir**. Bu, güvenen alanın içindeki bir kullanıcıya erişerek güvenilen alana girmek ve daha fazla yetki yükseltmeye çalışmak anlamına gelir:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Güvenilen alanı tehlikeye atmanın başka bir yolu, **alan güveni** yönünün **karşı yönde** oluşturulan bir [**SQL güvenilen bağlantısını**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Güvenilen alanı tehlikeye atmanın başka bir yolu, **güvenilen alanın bir kullanıcısının erişebileceği bir makinede beklemek** ve ardından **RDP** aracılığıyla oturum açmak olabilir. Daha sonra, saldırgan RDP oturumu sürecine kod enjekte edebilir ve buradan **kurbanın orijin alanına erişebilir**.\
Ayrıca, **kurbanın sabit diski bağladığı** durumda, saldırgan RDP oturumu sürecinden **sabit diskin başlangıç klasörüne** **arka kapılar** saklayabilir. Bu teknik **RDPInception** olarak adlandırılır.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Alan güveni kötüye kullanımı önleme

### **SID Filtreleme:**

* Orman güvenleri arasında SID geçmiş özniteliğini kullanarak yapılan saldırı riski, tüm orman güvenlerinde varsayılan olarak etkinleştirilen SID Filtreleme ile azaltılır. Bu, Microsoft'un duruşuna göre, ormanı, alanı değil, güvenlik sınırı olarak kabul ettiği varsayımına dayanmaktadır.
* Ancak, bir dezavantajı vardır: SID filtreleme, uygulamaları ve kullanıcı erişimini bozabilir ve bazen devre dışı bırakılabilir.

### **Seçmeli Kimlik Doğrulama:**

* Ormanlar arası güvenler için Seçmeli Kimlik Doğrulama kullanmak, iki ormandan gelen kullanıcıların otomatik olarak kimlik doğrulamasının yapılmamasını sağlar. Bunun yerine, güvenen alan veya ormandaki alanlara ve sunuculara erişim için kullanıcıların açık izinlere sahip olmaları gerekmektedir.
* Bu önlemlerin, yazılabilir Yapılandırma Adlandırma Bağlamı (NC) üzerindeki kötüye kullanımı veya güven hesabına yönelik saldırıları engellemediği önemlidir.

[**ired.team'de alan güvenleri hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Bazı Genel Savunmalar

[**Kimlik bilgilerini korumanın yolları hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)\\

### **Kimlik Bilgilerini Koruma İçin Savunma Önlemleri**

* **Alan Yöneticileri Kısıtlamaları**: Alan Yöneticilerinin yalnızca Alan Denetleyicilere giriş yapmaları ve diğer ana bilgisayarlarda kullanılmamaları önerilir.
* **Hizmet Hesabı Yetkileri**: Hizmetlerin Alan Yönetici (DA) ayrıcalıklarıyla çalıştırılmaması, güvenliği korumak için önemlidir.
* **Geçici Ayrıcalık Sınırlaması**: DA ayrıcalıklarını gerektiren görevler için süreleri sınırlamak önemlidir. Bu, şu şekilde başarılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Aldatma Tekniklerinin Uygulanması**

* Aldatma uygulamak, tuzağın kurulması anlamına gelir, örneğin süresi dolmayan veya Güvenilir Delege olarak işaretlenmiş şifreler gibi özelliklere sahip sahte kullanıcılar veya bilgisayarlar. Detaylı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya yüksek ayrıcalıklı gruplara eklemeyi içerir.
* Pratik bir örnek, şu araçların kullanılmasını içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Aldatma tekniklerinin uygulanması hakkında daha fazla bilgiye [GitHub'da Deploy-Deception](https://github.com/samratashok/Deploy-Deception) adresinden ulaşılabilir.

### **Aldatmanın Tanımlanması**

* **Kullanıcı Nesneleri İçin**: Şüpheli göstergeler, tipik olmayan ObjectSID, nadir oturum açma, oluşturma tarihleri ve düşük hatalı şifre sayıları içerebilir.
* **Genel Göstergeler**: Potansiyel sahte nesnelerin özniteliklerini gerçek nesnelerin öznitelikleriyle karşılaştırmak, tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar, bu tür aldatmaları tanımlamada yardımcı olabilir.

### **Algılama Sistemlerini Atlatma**

* **Microsoft ATA Algılama Atlatma**:
* **Kullanıcı Numaralandırma**: ATA algılama tetiklememek için Alan Denetleyicilerinde oturum numaralandırmasından kaçınılmalıdır.
* **Bilet Taklit**: Bilet oluşturmak için **aes** anahtarlarını kullanmak, NTLM'ye düşürülmemek suretiyle algılamadan kaçınmaya yardımcı olur.
* **DCSync Saldırıları**: ATA algılama tetiklememek için doğrudan bir Alan Denetleyicisinden değil, bir Alan Denetleyicisinden doğrudan yürütme yapılması tavsiye edilir.

## Referanslar

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin!</summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) olan [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u takip edin.
* Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek katkıda bulunun.

</details>
