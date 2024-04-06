# Active Directory Methodology

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek **hacking hilelerinizi paylaşın**.

</details>

## Temel genel bakış

**Active Directory**, ağ yöneticilerinin ağ içinde **alanlar**, **kullanıcılar** ve **nesneler** oluşturup yönetmelerini sağlayan temel bir teknoloji olarak hizmet verir. Ölçeklenebilir bir şekilde tasarlanmış olup, birçok kullanıcıyı yönetilebilir **gruplar** ve **alt gruplar** içinde düzenleyerek, çeşitli seviyelerde **erişim haklarını** kontrol etmeyi kolaylaştırır.

**Active Directory** yapısı üç temel katmandan oluşur: **alanlar**, **ağaçlar** ve **ormanlar**. Bir **alan**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesnelerin bir koleksiyonunu kapsar. **Ağaçlar**, bu alanları birleştiren ortak bir yapıya sahip olan alan gruplarıdır ve **orman**, bu ağaçların birbirleriyle **güven ilişkileri** aracılığıyla bağlantılı olduğu birden fazla ağacın koleksiyonunu temsil eder. Her bir seviyede belirli **erişim** ve **iletişim hakları** belirlenebilir.

**Active Directory** içindeki temel kavramlar şunlardır:

1. **Dizin** - Active Directory nesneleriyle ilgili tüm bilgileri içerir.
2. **Nesne** - Dizin içindeki varlıkları temsil eder, bunlar arasında **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** bulunur.
3. **Alan** - Dizin nesneleri için bir konteyner görevi görür ve her biri kendi nesne koleksiyonunu koruyan birden fazla alanın bir arada bulunmasına olanak tanır.
4. **Ağaç** - Ortak bir kök alanı paylaşan alanların bir gruplamasıdır.
5. **Orman** - Active Directory'deki organizasyon yapısının en üst katmanını oluşturan, birbirleriyle **güven ilişkileri** aracılığıyla bağlantılı birden fazla ağacı içeren bir koleksiyondur.

**Active Directory Domain Services (AD DS)**, bir ağ içinde merkezi yönetim ve iletişim için kritik öneme sahip bir dizi hizmeti kapsar. Bu hizmetler şunları içerir:

1. **Alan Hizmetleri** - Veri depolamasını merkezileştirir ve **kullanıcılar** ile **alanlar** arasındaki etkileşimleri yönetir, **kimlik doğrulama** ve **arama** işlevlerini içerir.
2. **Sertifika Hizmetleri** - Güvenli **dijital sertifikaların** oluşturulmasını, dağıtılmasını ve yönetimini denetler.
3. **Hafif Dizin Hizmetleri** - **LDAP protokolü** aracılığıyla dizin tabanlı uygulamaları destekler.
4. **Dizin Federasyon Hizmetleri** - Birden fazla web uygulamasında kullanıcıları **tek oturum açma** yetenekleri sağlar.
5. **Hak Yönetimi** - Telif hakkı materyallerinin izinsiz dağıtımını ve kullanımını düzenleyerek koruma sağlar.
6. **DNS Hizmeti** - **alan adlarının** çözülmesi için önemlidir.

Daha detaylı bir açıklama için şuraya bakın: [**TechTerms - Active Directory Tanımı**](https://techterms.com/definition/active\_directory)

### **Kerberos Kimlik Doğrulaması**

Bir AD'yi **saldırmak** için **Kerberos kimlik doğrulama sürecini** çok iyi anlamanız gerekmektedir.\
[Hala nasıl çalıştığını bilmiyorsanız, **bu sayfayı okuyun.**](kerberos-authentication.md)

## Hile Kağıdı

AD'yi sıralamak/istismar etmek için hangi komutları çalıştırabileceğinizi hızlı bir şekilde görmek için [https://wadcoms.github.io/](https://wadcoms.github.io) adresine gidebilirsiniz.

## Active Directory Keşfi (Kimlik bilgisi/oturum yok)

Eğer bir AD ortamına erişiminiz var ancak herhangi bir kimlik bilgisi/oturumunuz yoksa şunları yapabilirsiniz:

* **Ağı pentest edin:**
* Ağı taramalayın, makineleri ve açık portları bulun ve bunlardan **zafiyetleri istismar edin** veya **kimlik bilgilerini** çıkarın (örneğin, [yazıcılar çok ilginç hedefler olabilir](ad-information-in-printers.md)).
* DNS numaralandırma, alan içindeki ana sunucular hakkında bilgi verebilir, web, yazıcılar, paylaşımlar, vpn, medya vb.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Daha fazla bilgi için Genel [**Pentest Metodolojisi**](../../generic-methodologies-and-resources/pentesting-methodology.md)'ne bakın.
* **Smb hizmetlerinde boş ve Misafir erişimini kontrol edin** (bu modern Windows sürümlerinde çalışmayabilir):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Bir SMB sunucusunu nasıl numaralandıracağınıza dair daha ayrıntılı bir kılavuz burada bulunabilir:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Ldap numaralandırma**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* LDAP numaralandırmasının nasıl yapılacağına dair daha ayrıntılı bir kılavuz burada bulunabilir (özellikle anonim erişime **özel dikkat** gösterin):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

*

### Kullanıcı numaralandırma

* **Anonim SMB/LDAP numaralandırma:** [**Pentesting SMB**](../../network-services-pentesting/pentesting-smb/) ve [**Pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarını kontrol edin.
* **Kerbrute numaralandırma**: Bir **geçersiz kullanıcı adı istendiğinde**, sunucu **Kerberos hata** kodu olan _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_ kullanarak yanıt verecektir, bu da bize kullanıcı adının geçersiz olduğunu belirlememizi sağlar. **Geçerli kullanıcı adları**, ya bir AS-REP yanıtında **TGT'yi** veya kullanıcının ön kimlik doğrulaması yapması gerektiğini gösteren _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_ hatasını tetikleyecektir.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```

* **OWA (Outlook Web Access) Sunucusu**

Ağda böyle bir sunucu bulduysanız, bununla ilgili olarak **kullanıcı numaralandırması yapabilirsiniz**. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:

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
[**Bu GitHub deposunda**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) ve bu ([**istatistiksel-olasılıklı-kullanıcıadları**](https://github.com/insidetrust/statistically-likely-usernames)) listelerinde kullanıcı adlarını bulabilirsiniz.

Ancak, bu adımdan önce gerçekleştirmeniz gereken keşif adımından **şirkette çalışan insanların adını** bilmelisiniz. İsim ve soyadıyla, potansiyel geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) betiğini kullanabilirsiniz.
{% endhint %}

### Bir veya birkaç kullanıcı adını bilmek

Tamam, geçerli bir kullanıcı adınız olduğunu biliyorsunuz, ancak şifreleriniz yok... O zaman şunları deneyin:

* [**ASREPRoast**](asreproast.md): Bir kullanıcının _DONT\_REQ\_PREAUTH_ özniteliğine sahip **olmadığı durumlarda**, bu kullanıcı için bir AS\_REP mesajı **isteyebilirsiniz**. Bu mesaj, kullanıcının şifresinin türetilmesiyle şifrelenmiş bazı veriler içerecektir.
* [**Şifre Spreyi**](password-spraying.md): Keşfedilen her kullanıcı için en **sık kullanılan şifreleri** deneyin, belki bazı kullanıcılar kötü bir şifre kullanıyor (şifre politikasını göz önünde bulundurun!).
* Ayrıca, kullanıcıların posta sunucularına erişim elde etmek için **OWA sunucularına şifre spreyi** yapabilirsiniz.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Zehirlenmesi

Ağın bazı protokollerini **zehirleyerek** bazı meydan okuma **hash'leri** elde edebilirsiniz:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML İleti

Eğer etkin dizini numaralandırmayı başardıysanız, **daha fazla e-posta ve ağ hakkında daha iyi bir anlayışa sahip olacaksınız**. AD ortamına erişim elde etmek için NTML [**iletme saldırıları**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* yapabilirsiniz.

### NTML Kimlik Bilgilerini Çalma

**Null veya misafir kullanıcı** ile diğer PC'lere veya paylaşımlara **erişebiliyorsanız**, bir SCF dosyası gibi **dosyalar yerleştirebilirsiniz**. Bu dosyalara bir şekilde erişildiğinde, sizi hedefleyen bir NTML kimlik doğrulamasını tetikleyecektir, böylece NTML meydan okumasını çalabilirsiniz:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Kimlik bilgileri/oturumla birlikte Etkin Dizini Numaralandırma

Bu aşamada, **geçerli bir etki alanı hesabının kimlik bilgilerini veya oturumunu** ele geçirmeniz gerekmektedir. Geçerli kimlik bilgileriniz veya bir etki alanı kullanıcısı olarak bir kabuk elde ettiyseniz, **önceki seçeneklerin hala diğer kullanıcıları etkileme seçenekleri olduğunu** unutmayın.

Kimlik doğrulaması yapılan numaralandırmaya başlamadan önce **Kerberos çift atlama sorununu** bilmelisiniz.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Numaralandırma

Bir hesap ele geçirmek, tüm etki alanını ele geçirmeye başlamak için **büyük bir adımdır**, çünkü **Etkin Dizin Numaralandırmasına başlayabileceksiniz**:

[**ASREPRoast**](asreproast.md) ile artık herhangi bir potansiyel açık kullanıcıyı bulabilir ve [**Şifre Spreyi**](password-spraying.md) ile ele geçirilen hesabın şifresini, boş şifreleri ve umut verici yeni şifreleri deneyebilirsiniz.

* [**Temel bir keşif yapmak için CMD'yi kullanabilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
* Daha gizli olacak olan [**powershell ile keşif yapabilirsiniz**](../basic-powershell-for-pentesters/)
* Daha ayrıntılı bilgileri çıkarmak için [**powerview'ü kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md)
* Etkin bir dizinde keşif için harika bir araç olan [**BloodHound**](bloodhound.md). Kullanıcıların RDP yapabileceği yerleri bulun, diğer gruplara giden yolları bulun, vb.
* **Diğer otomatik AD numaralandırma araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* İlginç bilgiler içerebileceği için [**AD'nin DNS kayıtları**](ad-dns-records.md).
* Dizinin numaralandırılması için kullanabileceğiniz **GUI araç** olan **AdExplorer.exe** adlı araç SysInternal Suite'de bulunur.
* _userPassword_ ve _unixUserPassword_ alanlarında kimlik bilgilerini aramak veya _Description_ için bile **LDAP veritabanında arama yapabilirsiniz**. Diğer yöntemler için bkz. [PayloadsAllTheThings'teki AD Kullanıcı yorumunda şifre](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
* **Linux** kullanıyorsanız, etki alanını [**pywerview**](https://github.com/the-useless-one/pywerview) kullanarak numaralandırabilirsiniz.
* Ayrıca otomatik araçları da deneyebilirsiniz:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
* **Tüm etki alanı kullanıcılarını çıkarma**

Windows'ta tüm etki alanı kullanıcı adlarını elde etmek çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta ise şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Numaralandırma bölümü küçük görünse de, bu tümünün en önemli kısmıdır. Bağlantılara (özellikle cmd, powershell, powerview ve BloodHound'un bağlantısına) erişin, bir etki alanını nasıl numaralandıracağınızı öğrenin ve kendinizi rahat hissedene kadar pratik yapın. Bir değerlendirme sırasında, bu, DA'ya giden yolunuzu bulmanız veya hiçbir şey yapılamayacağına karar vermeniz için önemli bir an olacaktır.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetler tarafından kullanılan **TGS biletlerini** elde etmeyi ve şifrelerine dayanan şifrelemelerini **çevrimdışı** kırmayı içerir.

Daha fazlası için:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Uzaktan bağlantı (RDP, SSH, FTP, Win-RM, vb.)

Bazı kimlik bilgilerine sahip olduktan sonra herhangi bir **makineye erişiminizin olup olmadığını** kontrol edebilirsiniz. Bu amaçla, **CrackMapExec** kullanarak farklı protokollere sahip birkaç sunucuya bağlanmayı deneyebilirsiniz, taramalarınıza göre.

### Yerel Yetki Yükseltme

Eğer ele geçirdiğiniz kimlik bilgileri veya düzenli bir etki alanı kullanıcısı olarak bir oturumunuz varsa ve bu kullanıcıyla etki alanındaki **herhangi bir makineye erişiminiz varsa**, yerel olarak yetkilerinizi yükseltmek ve kimlik bilgileri çalmak için yolunuzu bulmaya çalışmalısınız. Bu, yalnızca yerel yönetici yetkilerine sahip olduğunuzda bellekte (LSASS) ve yerel olarak (SAM) diğer kullanıcıların hash'lerini çıkarabileceğiniz anlamına gelir.

Bu kitapta [**Windows'ta yerel yetki yükseltme**](../windows-local-privilege-escalation/) hakkında tam bir sayfa ve bir [**kontrol listesi**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Geçerli Oturum Biletleri

Geçerli kullanıcıda **izin verilmeyen kaynaklara erişim** sağlayan **biletler** bulmanız çok **olası değildir**, ancak kontrol edebilirsiniz:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTML Relay

Eğer aktif dizini numaralandırmayı başardıysanız, **daha fazla e-posta ve ağ hakkında daha iyi bir anlayışa sahip olacaksınız**. NTML [**röle saldırıları**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**nı** zorlayabilirsiniz.

### Bilgisayar Paylaşımlarında Kimlik Bilgilerini Arayın

Temel kimlik bilgilerine sahip olduğunuzda, AD içinde **paylaşılan ilginç dosyaları bulup bulamayacağınızı kontrol etmelisiniz**. Bunun için manuel olarak yapabilirsiniz, ancak bu çok sıkıcı ve tekrarlayan bir görevdir (ve yüzlerce belge bulursanız daha da sıkıcı olur).

[**Bu bağlantıyı takip ederek kullanabileceğiniz araçlar hakkında bilgi edinin.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### NTLM Kimlik Bilgilerini Çalma

Diğer bilgisayarlara veya paylaşımlara **erişebiliyorsanız**, bir SCF dosyası gibi **dosyalar yerleştirebilirsiniz**. Bu dosyalara herhangi bir şekilde erişildiğinde, size karşı bir NTML kimlik doğrulaması **tetikleyecektir**, böylece NTLM meydan okumasını çalabilirsiniz:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu zafiyet, herhangi bir yetkilendirilmiş kullanıcının **etki alanı denetleyicisini tehlikeye atmasına** izin veriyordu.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Ayrıcalık Yükseltme Aktif Dizinde AYRICALIKLI kimlik bilgileri/oturum ile

**Aşağıdaki teknikler için düzenli bir etki alanı kullanıcısı yeterli değildir, bu saldırıları gerçekleştirmek için özel ayrıcalıklar/kimlik bilgilerine ihtiyacınız vardır.**

### Hash çıkarma

Umarım [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) dahil olmak üzere yerel bir yönetici hesabını **tehlikeye atmayı başarmışsınızdır**, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [yerel ayrıcalıkları yükseltme](../windows-local-privilege-escalation/) gibi yöntemlerle.\
Daha sonra, bellekte ve yerel olarak tüm hash'leri dökme zamanı geldi.\
[**Farklı yollarla hash'leri elde etmek için bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/tr/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Hash'i Geçir

Bir kullanıcının hash'ine sahip olduktan sonra, onu **taklit etmek** için kullanabilirsiniz.\
Bu hash'i kullanarak **NTLM kimlik doğrulamasını gerçekleştirecek bir araç** kullanmanız gerekmektedir, **veya** yeni bir **oturum açma** oluşturabilir ve bu **hash'i** LSASS içine **enjekte** edebilirsiniz, böylece herhangi bir **NTLM kimlik doğrulaması gerçekleştirildiğinde** bu **hash kullanılacaktır**. Son seçenek mimikatz'ın yaptığı şeydir.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/#pass-the-hash)

### Hash'i Geçerek/Anahtarı Geçirerek

Bu saldırı, yaygın Pass The Hash üzerinden NTLM protokolü yerine, kullanıcı NTLM hash'ini Kerberos biletleri talep etmek için kullanmayı amaçlar. Bu nedenle, bu özellikle NTLM protokolünün devre dışı bırakıldığı ve yalnızca Kerberos'un yetkilendirme protokolü olarak izin verildiği ağlarda **faydalı olabilir**.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Bileti Geçir

**Bileti Geçirme (PTT)** saldırı yönteminde, saldırganlar bir kullanıcının parolasını veya hash değerlerini çalmak yerine, kullanıcının kimlik doğrulama bileti çalınır. Bu çalınan bilet daha sonra kullanılarak kullanıcı taklit edilir ve ağ içindeki kaynaklara ve hizmetlere izinsiz erişim sağlanır.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Kimlik Bilgilerini Yeniden Kullanma

Bir **yerel yönetici**nin hash'ine veya parolasına sahipseniz, bunu kullanarak diğer **PC'lere yerel olarak giriş yapmayı denemelisiniz**.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

{% hint style="warning" %}
Dikkat, bu oldukça **gürültülü** ve **LAPS** bunu **hafifletebilir**.
{% endhint %}

### MSSQL Kötüye Kullanımı ve Güvenilir Bağlantılar

Bir kullanıcının **MSSQL örneklerine erişim** yetkisi varsa, MSSQL ana bilgisayarında (SA olarak çalışıyorsa) **komutları yürütmek**, NetNTLM **hash'ini çalmak** veya hatta bir **aktarma** **saldırısı** gerçekleştirmek mümkün olabilir.\
Ayrıca, bir MSSQL örneği, başka bir MSSQL örneği tarafından güvenilir olarak kabul ediliyorsa (veritabanı bağlantısı). Kullanıcının güvenilen veritabanı üzerinde ayrıcalıkları varsa, diğer örnekte de sorguları yürütmek için **güven ilişkisini kullanabilecektir**. Bu güvenler zincirlenebilir ve kullanıcı, komutları yürütebileceği yanlış yapılandırılmış bir veritabanı bulabilir.\
**Veritabanları arasındaki bağlantılar orman güvenlerinin ötesinde çalışır.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Sınırsız Delege

Eğer [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) özelliğine sahip bir Bilgisayar nesnesi bulursanız ve bilgisayarda etki alanı ayrıcalıklarınız varsa, bilgisayara giriş yapan her kullanıcının TGT'lerini bellekten alabilirsiniz.\
Bu nedenle, bir **Etki Alanı Yöneticisi bilgisayara giriş yaptığında**, onun TGT'sini alabilir ve [Bileti Geçir](pass-the-ticket.md) kullanarak onun yerine geçebilirsiniz.\
Kısıtlanmış delege sayesinde, bir Yazıcı Sunucusu'nu bile **otomatik olarak ele geçirebilirsiniz** (umarım bir DC olur).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Kısıtlı Delege

Bir kullanıcıya veya bilgisayara "Kısıtlı Delege" izni verilirse, bir bilgisayarda bazı hizmetlere erişmek için herhangi bir kullanıcıyı **taklit edebilir**.\
Ardından, bu kullanıcı/bilgisayarın **hash'ini ele geçirirseniz**, bazı hizmetlere erişmek için herhangi bir kullanıcıyı (hatta etki alanı yöneticilerini) **taklit edebilirsiniz**.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Kaynak Tabanlı Kısıtlı Delege

Uzaktaki bir bilgisayarın Active Directory nesnesinde **YAZMA** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** kod yürütme elde etmeyi sağlar:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL Kötüye Kullanımı

Kompromize edilen kullanıcının, **bazı etki alanı nesneleri üzerinde ilginç ayrıcalıklara** sahip olabileceği ve bu da size yandan hareket etme/ayrıcalıkları yükseltme imkanı verebileceği olabilir.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Yazıcı Spooler hizmeti kötüye kullanımı

Etki alanında **Spool hizmeti dinleyen** bir hizmet keşfedilirse, bunun **kötüye kullanılması** yeni kimlik bilgileri edinmek ve ayrıcalıkları **yükseltmek** için kullanılabilir.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Üçüncü taraf oturumları kötüye kullanımı

Eğer **diğer kullanıcılar**, **kompromize edilmiş** makineye **erişim sağlarsa**, bellekten kimlik bilgilerini **toplamak** ve hatta onların süreçlerine **beacon enjekte etmek** için onları taklit etmek mümkün olabilir.\
Kullanıcılar genellikle RDP aracılığıyla sisteme erişirler, bu yüzden burada üçüncü taraf RDP oturumları üzerinde birkaç saldırı nasıl gerçekleştirilir:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Yönetici parolasını yönetmek** için bir sistem sağlar, bu parolanın **rastgele**, benzersiz ve sık sık **değiştirildiğini** sağlar. Bu parolalar Active Directory'de depolanır ve erişim sadece yetkilendirilmiş kullanıcılara yönelik olarak ACL'lerle kontrol edilir. Bu parolalara erişmek için yeterli izinlere sahip olmak, diğer bilgisayarlara geçiş yapmayı mümkün kılar.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Sertifika Hırsızlığı

Kompromize edilen makineden **sertifikaları toplamak**, ayrıcalıkları yükseltmek için bir yol olabilir:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Sertifika Şablonları Kötüye Kullanımı

**Zarar görebilir şablonlar** yapılandırılmışsa, ayrıcalıkları yükseltmek için bunları kötüye kullanmak mümkündür:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Yüksek ayrıcalıklı hesapla son aşama saldırıları

### Etki Alanı Kimlik Bilgilerini Dökme

Bir kez **Etki Alanı Yöneticisi** veya daha iyi **Kurumsal Yönetici** ayrıcalıklarına sahip olduğunuzda, **etki alanı veritabanını** (_ntds.dit_) **dökme** imkanınız olur.

[**DCSync saldırısı hakkında daha fazla bilgi burada bulunabilir**](dcsync.md).

[**NTDS.dit'yi çalmak için nasıl yapılacağı hakkında daha fazla bilgi burada bulunabilir**](https://github.com/carlospolop/hacktricks/blob/tr/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Ayrıcalıkların Kalıcı Olarak Yükseltilmesi

Önceden tartışılan bazı teknikler kalıcı olarak kullanılabilir.\
Örneğin:

* Kullanıcıları [**Kerberoast**](kerberoast.md) saldırısına karşı savunmasız hale getirebilirsiniz.

```powershell
Set-DomainObject -Identity <kullanıcıadı> -Set @{serviceprincipalname="fake/NOTHING"}r
```

* Kullanıcıları [**ASREPRoast**](asreproast.md) saldırısına karşı savunmasız hale getirebilirsiniz.

```powershell
Set-DomainObject -Identity <kullanıcıadı> -XOR @{UserAccountControl=4194304}
```

* Bir kullanıcıya [**DCSync**](./#dcsync) ayrıcalıkları verin

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Gümüş Bilet

**Gümüş Bilet saldırısı**, belirli bir hizmet için **meşru Birleşik Bilet Hizmeti (TGS) bileti** oluştururken (örneğin, PC hesabının hash'ini kullanarak) kullanılır. Bu yöntem, hizmet ayrıcalıklarına erişmek için kullanılır.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Altın Bilet

**Altın Bilet saldırısı**, bir Saldırganın bir Active Directory (AD) ortamında \*\*krbtgt hesabının NTLM hash

### **Sertifikalar Alan Kalıcılığı**

**Sertifikalar kullanılarak, etki alanı içinde yüksek ayrıcalıklarla kalıcılık sağlamak da mümkündür:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder Grubu

Active Directory'deki **AdminSDHolder** nesnesi, **Domain Admins** ve **Enterprise Admins** gibi **ayrıcalıklı grupların** güvenliğini sağlamak için bu gruplara yetkisiz değişiklikleri önlemek için standart bir **Erişim Kontrol Listesi (ACL)** uygular. Ancak, bu özellik kötüye kullanılabilir; saldırgan, AdminSDHolder'ın ACL'sini değiştirerek bir düzenli kullanıcıya tam erişim verirse, bu kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş kontrol sağlar. Bu koruma önlemi, korumak için tasarlanmış olsa da, yakından izlenmediği sürece istenmeyen erişime izin verebilir.

[**AdminDSHolder Grubu hakkında daha fazla bilgi burada.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Kimlik Bilgileri

Her **Domain Controller (DC)** içinde bir **yerel yönetici** hesabı bulunur. Böyle bir makinede yönetici hakları elde ederek, yerel Yönetici hash'i **mimikatz** kullanılarak çıkarılabilir. Bunun ardından, bu parolanın kullanımını **etkinleştirmek için bir kayıt defteri değişikliği** gereklidir, bu da uzaktan erişime olanak tanır.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL Kalıcılığı

Gelecekte ayrıcalıkları yükseltmek için bir kullanıcıya bazı belirli etki alanı nesneleri üzerinde **özel izinler** verebilirsiniz.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Güvenlik Tanımlayıcıları

**Güvenlik tanımlayıcıları**, bir **nesnenin** üzerindeki **izinleri** saklamak için kullanılır. Bir nesnenin güvenlik tanımlayıcısında küçük bir değişiklik yaparak, bir ayrıcalıklı gruba üye olmadan o nesne üzerinde çok ilginç ayrıcalıklar elde edebilirsiniz.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

Hafızadaki **LSASS**'ı değiştirerek, tüm etki alanı hesaplarına erişim sağlayan evrensel bir parola oluşturun.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Özel SSP

[SSP (Güvenlik Destek Sağlayıcısı) nedir öğrenin buradan.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Makineye erişim sağlamak için kullanılan kimlik bilgilerini **açık metin** olarak yakalamak için **kendi SSP'nizi** oluşturabilirsiniz.

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

AD'de yeni bir **Domain Controller** kaydeder ve belirli nesneler üzerinde (SIDHistory, SPN'ler...) özellikleri **günlüklerde herhangi bir iz bırakmadan** değiştirir. **DA** ayrıcalıklarına ve **kök etki alanı** içinde olmanız gerekmektedir.\
Yanlış veriler kullanırsanız, oldukça kötü günlükler ortaya çıkacaktır.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS Kalıcılığı

Daha önce, **LAPS parolalarını okuma izniniz varsa** ayrıcalıkları yükseltmek hakkında konuştuk. Bununla birlikte, bu parolalar kalıcılığı sağlamak için de kullanılabilir.\
Kontrol edin:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Orman Ayrıcalık Yükseltme - Etki Alanı Güveni

Microsoft, **Ormanı** güvenlik sınırları olarak görür. Bu, **tek bir etki alanının ele geçirilmesinin tüm Ormanın ele geçirilmesine yol açabileceği** anlamına gelir.

### Temel Bilgiler

[**Etki alanı güveni**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx), bir **etki alanından** başka bir **etki alanındaki kaynaklara erişimi** mümkün kılan bir güvenlik mekanizmasıdır. Temel olarak, iki etki alanının kimlik doğrulama sistemlerini birbirine bağlayan bir bağlantı oluşturur ve kimlik doğrulama doğrulamalarının sorunsuz bir şekilde akmasına izin verir. Etki alanları bir güven kurduklarında, **Domain Controller (DC)**'lerindeki belirli **anahtarları** değiş tokuş eder ve saklarlar, bu da güvenin bütünlüğü için önemlidir.

Tipik bir senaryoda, bir kullanıcının bir **güvenilen etki alanındaki** bir hizmete erişmek istemesi durumunda, önce kendi etki alanının DC'sinden bir **inter-realm TGT** olarak bilinen özel bir bilet talep etmesi gerekir. Bu TGT, her iki etki alanının da anlaştığı bir paylaşılan **anahtar** ile şifrelenir. Kullanıcı daha sonra bu TGT'yi **güvenilen etki alanının DC'sine** sunarak bir hizmet bileti (**TGS**) alır. Güvenilen etki alanının DC'si, güvenilen etki alanının DC'si tarafından inter-realm TGT'nin başarılı bir şekilde doğrulanması durumunda, kullanıcıya hizmete erişim izni veren bir TGS verir.

**Adımlar**:

1. **Domain 1**'deki bir **istemci bilgisayar**, **NTLM hash**'ini kullanarak **Domain Controller (DC1)**'den bir **Ticket Granting Ticket (TGT)** talep ederek işlemi başlatır.
2. DC1, istemci başarılı bir şekilde kimlik doğrulandığında yeni bir TGT verir.
3. İstemci daha sonra, **Domain 2**'deki kaynaklara erişmek için gereken **inter-realm TGT**'yi DC1'den talep eder.
4. İnter-realm TGT, DC1 ve DC2 arasında paylaşılan bir **güven anahtarı** ile şifrelenir ve iki yönlü etki alanı güveninin bir parçası olarak saklanır.
5. İstemci, inter-realm TGT'yi **Domain 2'nin Domain Controller'ına (DC2)** götürür.
6. DC2, paylaşılan güven anahtarını kullanarak inter-realm TGT'yi doğrular ve geçerliyse, istemcinin Domain 2'deki hizmete erişmek istediği sunucu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak, istemci bu TGS'yi sunucuya sunar ve hizmete erişim sağlar.

### Farklı güvenler

**Bir güvenin tek yönlü veya iki yönlü olabileceğini** fark etmek önemlidir. İki yönlü seçeneklerde, her iki etki alanı da birbirine güvenir, ancak **tek yönlü** güven ilişkisinde bir etki alanı **güvenilen** etki alanı olurken diğeri **güvenen** etki alanı olur. Son durumda, \*\*güvenilen etki alanından güven

#### Güven ilişkilerindeki diğer farklar

* Bir güven ilişkisi aynı zamanda **geçişli** (A, B'ye güvenir, B, C'ye güvenir, o zaman A, C'ye güvenir) veya **geçişsiz** olabilir.
* Bir güven ilişkisi **iki yönlü güven** (her ikisi de birbirine güvenir) veya **tek yönlü güven** (sadece biri diğerine güvenir) olarak kurulabilir.

### Saldırı Yolu

1. Güven ilişkilerini **sırala**
2. Herhangi bir **güvenlik prensibi**nin (kullanıcı/grup/bilgisayar) **diğer etki alanının kaynaklarına erişimi** olup olmadığını kontrol et, muhtemelen ACE girişleri veya diğer etki alanının gruplarında bulunarak. **Etki alanları arasındaki ilişkilere** bak (güven ilişkisi muhtemelen bunun için oluşturuldu).
3. Bu durumda kerberoast başka bir seçenek olabilir.
4. Etki alanları arasında **geçiş yapabilen hesapları** **ele geçir**.

Saldırganlar, başka bir etki alanındaki kaynaklara üç temel mekanizma aracılığıyla erişebilir:

* **Yerel Grup Üyeliği**: Prensipaller, bir sunucudaki "Yöneticiler" grubu gibi makinelerdeki yerel gruplara eklenmiş olabilir, bu da onlara o makine üzerinde önemli bir kontrol sağlar.
* **Yabancı Etki Alanı Grup Üyeliği**: Prensipaller ayrıca yabancı etki alanındaki grupların üyeleri olabilir. Bunun etkinliği, güvenin doğası ve grup kapsamına bağlıdır.
* **Erişim Kontrol Listeleri (ACL'ler)**: Prensipaller, özellikle bir **DACL** içindeki **ACE'ler** olarak var olan **ACL'lerde** belirtilebilir, bu da onlara belirli kaynaklara erişim sağlar. ACL'lerin, DACL'lerin ve ACE'lerin mekaniği hakkında daha derinlemesine bilgi edinmek isteyenler için "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)" adlı beyaz kağıt çok değerli bir kaynaktır.

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
**2 güvenilir anahtar** bulunmaktadır, biri _Çocuk --> Ebeveyn_ için diğeri ise _Ebeveyn_ --> _Çocuk_ için kullanılır.\
Mevcut etki alanı tarafından kullanılan anahtarı aşağıdaki komutla alabilirsiniz:

```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

SID-History enjeksiyonuyla güveni istismar ederek çocuk/ana etki alanında Kurumsal yönetici olarak yükseltme:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Yazılabilir Yapılandırma NC'sini Sömürme

Yapılandırma NC'sinin nasıl sömürülebileceğini anlamak önemlidir. Yapılandırma NC, Active Directory (AD) ortamlarında bir ormanda yapılandırma verilerinin merkezi bir depolama alanı olarak hizmet verir. Bu veriler, ormanda bulunan her bir Etki Alanı Denetleyicisi'ne (DC) replike edilir ve yazılabilir DC'ler, Yazılabilir Yapılandırma NC'nin yazılabilir bir kopyasını tutar. Bunun sömürülmesi için, tercihen bir çocuk DC'sinde **SİSTEM ayrıcalıklarına** sahip olunmalıdır.

**GPO'yu kök DC sitesine bağlama**

Yapılandırma NC'nin Siteler konteyneri, AD ormanı içindeki tüm etki alanına katılan bilgisayarların siteleri hakkında bilgi içerir. Saldırganlar, herhangi bir DC üzerinde SİSTEM ayrıcalıklarıyla çalışarak GPO'ları kök DC sitelerine bağlayabilir. Bu eylem, bu sitelere uygulanan politikaları manipüle ederek kök etki alanını potansiyel olarak tehlikeye atar.

Ayrıntılı bilgi için, [SID Filtrelemesini Atlatma](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) üzerine yapılan araştırmaları inceleyebilirsiniz.

**Ormandaki herhangi bir gMSA'yı ele geçirme**

Bir saldırı vektörü, etki alanı içindeki ayrıcalıklı gMSA'ları hedef almaktır. gMSA'ların şifrelerini hesaplamak için gereken KDS Kök anahtarı, Yapılandırma NC içinde depolanır. Herhangi bir DC üzerinde SİSTEM ayrıcalıklarıyla, KDS Kök anahtarına erişmek ve ormandaki herhangi bir gMSA'nın şifrelerini hesaplamak mümkündür.

Detaylı analiz, [Golden gMSA Trust Saldırıları](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent) üzerinde bulunabilir.

**Şema değişikliği saldırısı**

Bu yöntem sabır gerektirir, yeni ayrıcalıklı AD nesnelerinin oluşturulmasını beklemek gerekir. SİSTEM ayrıcalıklarıyla bir saldırgan, AD Şemasını değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verme yeteneğine sahip olabilir. Bu, yetkisiz erişim ve yeni oluşturulan AD nesneleri üzerinde kontrol sağlayabilir.

Daha fazla bilgi için, [Şema Değişikliği Trust Saldırıları](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) mevcuttur.

**ADCS ESC5 ile DA'dan EA'ya**

ADCS ESC5 zafiyeti, PKI nesneleri üzerinde kontrol sağlamak için kullanılır ve ormandaki herhangi bir kullanıcı olarak kimlik doğrulamasını mümkün kılan bir sertifika şablonu oluşturur. PKI nesneleri, Yapılandırma NC içinde bulunduğu için, yazılabilir bir çocuk DC'nin ele geçirilmesi ESC5 saldırılarının gerçekleştirilmesine olanak sağlar.

Bu konuda daha fazla ayrıntı [DA'dan EA'ya ESC5 ile](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) okunabilir. ADCS olmayan senaryolarda, saldırgan gerekli bileşenleri kurma yeteneğine sahiptir, bu da [Çocuk Etki Alanı Yöneticilerinden Kurumsal Yöneticilere Yükselme](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) olarak tartışılmıştır.

### Harici Orman Etki Alanı - Tek Yönlü (Gelen) veya İki Yönlü

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

Bu senaryoda, **alanınızın dışarıdan biri tarafından güvenildiği** ve size **belirlenmemiş izinler** verildiği varsayılır. İlk olarak, **alanınızın prensiplerinin dış alan üzerinde hangi erişime sahip olduğunu bulmanız** gerekmektedir ve ardından bunu sömürmeye çalışmanız gerekmektedir:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Dış Orman Alanı - Tek Yönlü (Dışarıya Doğru)

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

Bu senaryoda **alanınız**, bir **farklı alanlardan** birincil birine bazı **ayrıcalıklar** sağlamaktadır.

Ancak, bir alan, güvenen alan tarafından güvenilen bir alan olduğunda, güvenilen alan, güvenilen parolayı kullanarak tahmin edilebilir bir isimle bir kullanıcı oluşturur. Bu da, güvenen alanın içine girmek için güvenen alanın içindeki bir kullanıcıya erişmek mümkün olduğu anlamına gelir ve daha fazla ayrıcalık elde etmek için onu sıralamak için:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Güvenilen alanı tehlikeye atmanın başka bir yolu, alan güveninin **ters yönde** oluşturulan bir [**SQL güvenilen bağlantı**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Güvenilen alanı tehlikeye atmanın başka bir yolu, güvenilen alanın erişebileceği bir makinede beklemektir ve ardından saldırgan RDP oturumu sürecine kod enjekte edebilir ve oradan kurbanın kaynak alanına erişebilir.\
Dahası, **kurban sabit diski bağladıysa**, saldırgan RDP oturumu sürecinden **sabotajlar**ı **sabit diskin başlangıç klasörüne** kaydedebilir. Bu teknik **RDPInception** olarak adlandırılır.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Alan güveni kötüye kullanımının önlenmesi

### **SID Filtreleme:**

* Orman güvenleri arasında SID geçmişi özniteliğini kullanarak yapılan saldırı riski, SID Filtreleme ile azaltılır ve bu, tüm ormanlar arası güvenlere varsayılan olarak etkinleştirilir. Bu, Microsoft'un duruşuna göre, güvenlik sınırının alan yerine orman olduğu varsayımına dayanmaktadır.
* Ancak, bir dezavantajı vardır: SID filtreleme, uygulamaları ve kullanıcı erişimini bozabilir ve bu nedenle bazen devre dışı bırakılabilir.

### **Seçici Kimlik Doğrulama:**

* Ormanlar arası güvenler için, Seçici Kimlik Doğrulama kullanarak, iki ormandan gelen kullanıcıların otomatik olarak kimlik doğrulamasının yapılmaması sağlanır. Bunun yerine, kullanıcıların güvenen alan veya ormanda bulunan alanlara ve sunuculara erişmek için açık izinlere sahip olmaları gerekmektedir.
* Bu önlemlerin, yazılabilir Yapılandırma Adlandırma Bağlamı (NC) üzerindeki istismar veya güven hesabına yönelik saldırılara karşı koruma sağlamadığını unutmak önemlidir.

[**ired.team'de alan güvenleri hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Bazı Genel Savunmalar

[**Kimlik bilgilerini korumanın nasıl yapılacağı hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)\\

### **Kimlik Bilgilerini Koruma İçin Savunma Önlemleri**

* **Alan Yöneticileri Kısıtlamaları**: Alan Yöneticilerinin yalnızca Alan Denetleyicilerine giriş yapmasına izin verilmesi, diğer ana bilgisayarlarda kullanılmaması önerilir.
* **Hizmet Hesabı Ayrıcalıkları**: Hizmetlerin Alan Yöneticisi (DA) ayrıcalıklarıyla çalıştırılmaması, güvenliği korumak için gereklidir.
* **Geçici Ayrıcalık Sınırlaması**: DA ayrıcalıklarını gerektiren görevlerin süresi sınırlı olmalıdır. Bu, şu şekilde elde edilebilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Aldatma Tekniklerinin Uygulanması**

* Aldatma uygulamak, aldatıcı kullanıcılar veya bilgisayarlar gibi tuzaklar kurmayı içerir ve bunlar, süresi dolmayan veya Güvenilir Delege olarak işaretlenen şifreler gibi özelliklere sahip olabilir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya bunları yüksek ayrıcalıklı gruplara eklemeyi içerir.
* Pratik bir örnek, `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose` gibi araçların kullanılmasıyla gerçekleştirilebilir.
* Aldatma tekniklerinin nasıl uygulanacağı hakkında daha fazla bilgi için [GitHub'da Deploy-Deception](https://github.com/samratashok/Deploy-Deception) adresine bakabilirsiniz.

### **Aldatmanın Belirlenmesi**

* **Kullanıcı Nesneleri İçin**: Şüpheli göstergeler, tipik olmayan ObjectSID, seyrek oturum açma, oluşturma tarihleri ve düşük hatalı parola sayıları içerebilir.
* **Genel Göstergeler**: Potansiyel aldatıcı nesnelerin özniteliklerini gerçek olanların öznitelikleriyle karşılaştırmak, tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar, bu tür aldatmaların belirlenmesine yardımcı olabilir.

### **Algılama Sistemlerini Atlama**

* **Microsoft ATA Algılama Atlama**:
* **Kullanıcı Numaralandırma**: ATA algılama tetiklememek için Alan Denetleyicilerinde oturum numaralandırmaktan kaçınılmalıdır.
* **Bilet Taklit**: NTLM'ye düşürülmemek için **aes** anahtarlarını bilet oluşturmak için kullanmak, algılamadan kaçınmaya yardımcı olur.
* **DCSync Saldırıları**: ATA algılama tetiklememek için bir Alan Denetleyicisinden doğrudan yürütme yerine bir Alan Denetleyicisinden olmayan bir yerden yürütülmesi önerilir.

## Referanslar

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>ile sıfırdan kahramana kadar AWS hackleme öğrenin</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live).
* \*\*Hacking hilelerinizi HackTricks ve HackTricks Cloud github depolarına PR gönder

</details>
