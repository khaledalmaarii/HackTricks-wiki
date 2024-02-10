# macOS Red Teaming

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>

## MDM'leri Kötüye Kullanma

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Yönetim platformuna erişmek için **yönetici kimlik bilgilerini ele geçirmeyi** başarırsanız, kötü amaçlı yazılımınızı makinelerde dağıtarak **potansiyel olarak tüm bilgisayarları tehlikeye atabilirsiniz**.

MacOS ortamlarında kırmızı takım çalışması yaparken MDM'lerin nasıl çalıştığı hakkında biraz anlayışa sahip olmanız **şiddetle önerilir**:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDM'yi C2 Olarak Kullanma

Bir MDM, profil yükleme, sorgulama veya kaldırma, uygulama yükleme, yerel yönetici hesapları oluşturma, firmware şifresi ayarlama, FileVault anahtarını değiştirme gibi izinlere sahip olacaktır...

Kendi MDM'nizi çalıştırmak için [**https://mdmcert.download/**](https://mdmcert.download/) adresinden elde etmeye çalışabileceğiniz bir satıcı tarafından imzalanan **CSR'ınıza** ihtiyacınız vardır. Apple cihazları için kendi MDM'nizi çalıştırmak için [**MicroMDM**](https://github.com/micromdm/micromdm) kullanabilirsiniz.

Ancak, kayıtlı bir cihaza bir uygulama yüklemek için hala bir geliştirici hesabı tarafından imzalanmış olması gerekmektedir... ancak, MDM kaydı sırasında **cihaz, MDM'nin SSL sertifikasını güvenilir bir CA olarak ekler**, böylece artık herhangi bir şeyi imzalayabilirsiniz.

Bir cihazı MDM'ye kaydetmek için kök olarak bir **`mobileconfig`** dosyası yüklemeniz gerekmektedir, bu dosya bir **pkg** dosyası aracılığıyla teslim edilebilir (zip içinde sıkıştırabilir ve Safari'den indirildiğinde açılacaktır).

**Mythic agent Orthrus** bu tekniği kullanır.

### JAMF PRO'yu Kötüye Kullanma

JAMF, **özel komut dosyaları** (sistem yöneticisi tarafından geliştirilen komut dosyaları), **yerel yükler** (yerel hesap oluşturma, EFI şifresi ayarlama, dosya/süreç izleme...) ve **MDM** (cihaz yapılandırmaları, cihaz sertifikaları...) çalıştırabilir.

#### JAMF otomatik kaydı

`https://<şirket-adı>.jamfcloud.com/enroll/` gibi bir sayfaya giderek **otomatik kaydın etkin olup olmadığını** kontrol edebilirsiniz. Etkinse **erişim için kimlik bilgileri isteyebilir**.

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) betiğini kullanarak bir parola sıçratma saldırısı gerçekleştirebilirsiniz.

Ayrıca, uygun kimlik bilgilerini bulduktan sonra diğer kullanıcı adlarını brute-force yöntemiyle deneyebilirsiniz:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### JAMF cihaz Kimlik Doğrulama

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`** ikili dosyası, keşif zamanında herkesle **paylaşılan** anahtar zincirini açmak için gizli anahtarı içeriyordu: **`jk23ucnq91jfu9aj`**.\
Ayrıca, jamf **LaunchDaemon** olarak **`/Library/LaunchAgents/com.jamf.management.agent.plist`** konumunda kalıcı olarak çalışır.

#### JAMF Cihaz Devralma

**`jamf`**'ın kullanacağı **JSS** (Jamf Yazılım Sunucusu) **URL**'si **`/Library/Preferences/com.jamfsoftware.jamf.plist`** konumundadır.\
Bu dosya temel olarak URL'yi içerir:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Böylece, bir saldırgan, bu dosyayı üzerine yazan kötü amaçlı bir paket (`pkg`) bırakabilir ve kurulduğunda **URL'yi Typhon ajanından bir Mythic C2 dinleyicisine ayarlayabilir**, böylece JAMF'ı C2 olarak kullanabilir.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Taklit Etme

Bir cihaz ve JMF arasındaki iletişimi **taklit etmek** için şunlara ihtiyacınız vardır:

* Cihazın **UUID**'si: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Cihaz sertifikasını içeren **JAMF anahtar zinciri**: `/Library/Application\ Support/Jamf/JAMF.keychain`

Bu bilgilerle, **çalınan** Donanım **UUID**'ye sahip ve **SIP devre dışı** bırakılmış bir VM **oluşturun**, **JAMF anahtar zincirini** bırakın, Jamf **ajanını** **kancalayın** ve bilgilerini çalın.

#### Sırların Çalınması

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ayrıca, **özel betikleri** Jamf aracılığıyla çalıştırmak isteyebilecek yöneticilerin yerini izleyebilirsiniz. Bu betikler buraya yerleştirilir, çalıştırılır ve kaldırılır. Bu betikler **kimlik bilgilerini içerebilir**.

Ancak, **kimlik bilgileri** bu betiklere **parametreler** olarak geçirilebilir, bu yüzden `ps aux | grep -i jamf`'ı (root olmadan bile) izlemeniz gerekecektir.

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) adlı betik, yeni dosyaların eklenmesini ve yeni işlem argümanlarını dinleyebilir.

### macOS Uzaktan Erişim

Ve ayrıca **MacOS** "özel" **ağ** **protokolleri** hakkında:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Bazı durumlarda **MacOS bilgisayarının bir AD'ye bağlı olduğunu** göreceksiniz. Bu senaryoda, alıştığınız gibi aktif dizini **numaralandırmaya** çalışmalısınız. Aşağıdaki sayfalarda **yardım** bulun:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Size yardımcı olabilecek bazı **yerel MacOS araçları** `dscl`'dir:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Ayrıca, MacOS için AD'yi otomatik olarak sıralamak ve kerberos ile oynamak için bazı araçlar hazırlanmıştır:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound, MacOS ana bilgisayarlarında Active Directory ilişkilerini toplamaya ve içe aktarmaya izin veren Bloodhound denetim aracının bir uzantısıdır.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost, macOS üzerinde Heimdal krb5 API'leri ile etkileşim kurmak için tasarlanmış bir Objective-C projesidir. Projenin amacı, hedefte başka bir çerçeve veya paket gerektirmeden yerel API'leri kullanarak macOS cihazlarında Kerberos etrafında daha iyi güvenlik testleri yapmaktır.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory sıralaması yapmak için JavaScript for Automation (JXA) aracı.

### Alan Bilgisi
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Kullanıcılar

MacOS kullanıcılarının üç türü vardır:

* **Yerel Kullanıcılar** - Yerel OpenDirectory hizmeti tarafından yönetilen, Active Directory ile herhangi bir şekilde bağlantılı olmayan kullanıcılardır.
* **Ağ Kullanıcıları** - Geçici Active Directory kullanıcılarıdır ve kimlik doğrulaması için DC sunucusuna bağlantı gerektirirler.
* **Mobil Kullanıcılar** - Kimlik bilgileri ve dosyaları için yerel bir yedek olan Active Directory kullanıcılarıdır.

Kullanıcılar ve gruplar hakkındaki yerel bilgiler, _/var/db/dslocal/nodes/Default_ klasöründe saklanır.\
Örneğin, _mark_ adlı kullanıcıyla ilgili bilgiler _/var/db/dslocal/nodes/Default/users/mark.plist_ dosyasında saklanır ve _admin_ adlı grupla ilgili bilgiler _/var/db/dslocal/nodes/Default/groups/admin.plist_ dosyasında bulunur.

MacHound, Bloodhound veritabanına HasSession ve AdminTo kenarlarına ek olarak **üç yeni kenar** ekler:

* **CanSSH** - ana bilgisayara SSH yapmaya izin verilen varlık
* **CanVNC** - ana bilgisayara VNC yapmaya izin verilen varlık
* **CanAE** - ana bilgisayarda AppleEvent komut dosyalarını çalıştırmaya izin verilen varlık
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Daha fazla bilgi için [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/) adresine bakabilirsiniz.

## Keychain'e Erişim

Keychain, muhtemelen bir prompt oluşturmadan erişilen hassas bilgileri içerir ve bu da bir kırmızı takım egzersizinde ilerlemeye yardımcı olabilir:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Harici Hizmetler

MacOS Kırmızı Takım çalışması, genellikle **MacOS'un doğrudan birkaç harici platformla entegre olduğu** normal bir Windows Kırmızı Takım çalışmasından farklıdır. MacOS'un yaygın bir yapılandırması, **OneLogin senkronize kimlik bilgileri kullanarak bilgisayara erişim sağlamak ve OneLogin aracılığıyla birkaç harici hizmete** (github, aws gibi) erişmektir.

## Çeşitli Kırmızı Takım teknikleri

### Safari

Safari'de bir dosya indirildiğinde, eğer "güvenli" bir dosya ise, **otomatik olarak açılır**. Örneğin, bir zip dosyası indirirseniz, otomatik olarak açılır:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Referanslar

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud github reposuna PR göndererek paylaşın.**

</details>
