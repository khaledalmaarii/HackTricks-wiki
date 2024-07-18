{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip et.**
* **Hacking püf noktalarını göndererek HackTricks ve HackTricks Cloud** github depolarına PR gönder.

</details>
{% endhint %}


## smss.exe

**Oturum Yöneticisi**.\
Oturum 0, **csrss.exe** ve **wininit.exe** (**İşletim Sistemi hizmetleri**) başlatırken Oturum 1, **csrss.exe** ve **winlogon.exe** (**Kullanıcı oturumu**) başlatır. Ancak, bu **binary**'nin **çocuksuz** bir **süreç ağacında** görünmesi gerekmektedir.

Ayrıca, 0 ve 1'den farklı oturumlar, RDP oturumlarının gerçekleştiği anlamına gelebilir.


## csrss.exe

**İstemci/Sunucu Çalışma Alt Sistemi Süreci**.\
**Süreçleri** ve **iş parçacıklarını** yönetir, **Windows API**'yi diğer süreçler için kullanılabilir hale getirir ve ayrıca **sürücü harflerini eşler**, **geçici dosyalar oluşturur** ve **kapatma işlemini** yönetir.

Oturum 0'da bir tane **çalışırken ve Oturum 1'de bir tane** olmak üzere (bu nedenle süreç ağacında **2 süreç** bulunmaktadır). Yeni bir Oturum başına başka bir tane oluşturulur.


## winlogon.exe

**Windows Oturum Açma Süreci**.\
Kullanıcı **oturum açma**/**oturum kapatma** işlemlerinden sorumludur. Kullanıcı adı ve şifre istemek için **logonui.exe**'yi başlatır ve ardından bunları doğrulamak için **lsass.exe**'yi çağırır.

Daha sonra, **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**'da belirtilen **Userinit** anahtarıyla **userinit.exe**'yi başlatır.

Ayrıca, önceki kayıt defterinde **Shell anahtarında explorer.exe**'nin olması gerekmektedir veya bu, **kötü amaçlı yazılım kalıcılık yöntemi** olarak kötüye kullanılabilir.


## wininit.exe

**Windows Başlatma Süreci**. \
Oturum 0'da **services.exe**, **lsass.exe** ve **lsm.exe**'yi başlatır. Yalnızca 1 süreç olmalıdır.


## userinit.exe

**Kullanıcı Oturum Açma Uygulaması**.\
**HKCU'da ntduser.dat**'ı yükler ve **kullanıcı ortamını başlatır** ve **oturum açma betiklerini** ve **GPO'ları** çalıştırır.

**explorer.exe**'yi başlatır.


## lsm.exe

**Yerel Oturum Yöneticisi**.\
Kullanıcı oturumlarını yönetmek için smss.exe ile çalışır: Oturum açma/kapatma, kabuk başlatma, masaüstünü kilitleme/açma vb.

W7'den sonra lsm.exe bir hizmete (lsm.dll) dönüştürüldü.

W7'de yalnızca 1 süreç olmalıdır ve bunlardan biri DLL çalıştıran bir hizmettir.


## services.exe

**Hizmet Kontrol Yöneticisi**.\
**Otomatik başlangıç** ve **sürücüler** olarak yapılandırılmış **hizmetleri yükler**.

**svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** ve daha birçok sürecin ana sürecidir.

Hizmetler, `HKLM\SYSTEM\CurrentControlSet\Services` içinde tanımlanmıştır ve bu süreç, hizmet bilgilerinin bellekteki bir veritabanını sorgulayabileceği bir DB'yi korur.

**Bazı hizmetlerin kendi süreçlerinde** çalışacağına **dikkat edin** ve diğerlerinin **svchost.exe sürecini paylaşacağına dikkat edin**.

Yalnızca 1 süreç olmalıdır.


## lsass.exe

**Yerel Güvenlik Otoritesi Alt Sistemi**.\
Kullanıcı **kimlik doğrulamasından sorumludur** ve **güvenlik** **jetonları** oluşturur. `HKLM\System\CurrentControlSet\Control\Lsa` konumunda bulunan kimlik doğrulama paketlerini kullanır.

**Güvenlik** **etkinlik** **günlüğüne yazılır** ve yalnızca 1 süreç olmalıdır.

Bu sürecin şifreleri çalmak için yoğun bir şekilde saldırıya uğradığını unutmayın.


## svchost.exe

**Genel Hizmet Ana Bilgisayar Süreci**.\
Birden fazla DLL hizmetini tek bir paylaşılan süreçte barındırır.

Genellikle **svchost.exe**'nin **-k** bayrağıyla başlatıldığını göreceksiniz. Bu, aynı süreçte başlatılacak hizmetleri içeren **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** kaydına bir argümanla bir sorgu başlatacaktır.

Örneğin: `-k UnistackSvcGroup` şunları başlatacaktır: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

**-s bayrağı** belirli bir hizmeti başlatması isteniyorsa, svchost'a yalnızca bu argümanla belirtilen hizmeti başlatması istenir.

`svchost.exe`'nin birkaç süreci olacaktır. Bunlardan herhangi biri **-k** bayrağı kullanmıyorsa, bu çok şüphelidir. **services.exe'nin ebeveyn olmadığını** bulursanız, bu da çok şüphelidir.


## taskhost.exe

Bu süreç, DLL'lerden çalışan süreçler için bir ana bilgisayar olarak hareket eder. Ayrıca DLL'lerden çalışan hizmetleri yükler.

W8'de bu taskhostex.exe olarak adlandırılır ve W10'da taskhostw.exe olarak adlandırılır.


## explorer.exe

Bu, **kullanıcının masaüstünden** sorumlu süreçtir ve dosyaları dosya uzantıları aracılığıyla başlatır.

**Giriş yapan kullanıcı başına yalnızca 1** süreç oluşturulmalıdır.

Bu, **userinit.exe**'den çalıştırılır ve bu nedenle bu süreç için **ebeveyn** görünmemelidir.


# Zararlı Süreçleri Yakalama

* Beklenen yoldan mı çalışıyor? (Windows binary dosyaları geçici konumdan çalıştırılmaz)
* Garip IP adresleriyle iletişim kuruyor mu?
* Dijital imzaları kontrol edin (Microsoft ürünleri imzalı olmalıdır)
* Doğru yazılmış mı?
* Beklenen SID altında mı çalışıyor?
* Ebeveyn süreç beklenen mi (varsa)?
* Çocuk süreçler beklenen mi? (cmd.exe, wscript.exe, powershell.exe yok mu?)
{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip et.**
* **Hacking püf noktalarını göndererek HackTricks ve HackTricks Cloud** github depolarına PR gönder.

</details>
{% endhint %}
