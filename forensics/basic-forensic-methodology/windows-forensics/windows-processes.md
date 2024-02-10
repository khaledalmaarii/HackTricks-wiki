<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'i **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


## smss.exe

**Oturum Yöneticisi**.\
Oturum 0, **csrss.exe** ve **wininit.exe** (**İşletim Sistemi** **hizmetleri**)'yi başlatırken, Oturum 1, **csrss.exe** ve **winlogon.exe** (**Kullanıcı** **oturumu**)'yu başlatır. Bununla birlikte, işlem ağacında **yalnızca bir tane** bu **ikili**nin çocuksuz bir işlemi olduğunu görmelisiniz.

Ayrıca, 0 ve 1'den farklı oturumlar, RDP oturumlarının gerçekleştiği anlamına gelebilir.


## csrss.exe

**İstemci/Sunucu Çalışma Alt Sistemi İşlemi**.\
**İşlemleri** ve **iş parçacıklarını** yönetir, diğer işlemler için **Windows** **API**'yi kullanılabilir hale getirir ve ayrıca **sürücü harflerini eşler**, **geçici dosyalar** oluşturur ve **kapanma işlemini** yönetir.

Oturum 0'da bir tane **çalışırken, Oturum 1'de bir tane daha** vardır (bu nedenle işlem ağacında **2 işlem** bulunur). Yeni bir Oturum başına başka bir tane oluşturulur.


## winlogon.exe

**Windows Oturum Açma İşlemi**.\
Kullanıcı **oturum açma**/**oturum kapatma** işlemlerinden sorumludur. Kullanıcı adı ve parola sormak için **logonui.exe**'yi başlatır ve ardından bunları doğrulamak için **lsass.exe**'yi çağırır.

Ardından, **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**'da **Userinit** anahtarıyla belirtilen **userinit.exe**'yi başlatır.

Ayrıca, önceki kayıt defterinde **Shell anahtarında explorer.exe** olmalı veya kötü amaçlı yazılım kalıcılık yöntemi olarak istismar edilebilir.


## wininit.exe

**Windows Başlatma İşlemi**. \
Oturum 0'da **services.exe**, **lsass.exe** ve **lsm.exe**'yi başlatır. Yalnızca 1 işlem olmalıdır.


## userinit.exe

**Userinit Oturum Açma Uygulaması**.\
**ntuser.dat'ı HKCU'da** yükler ve **kullanıcı** **ortamını** başlatır, **oturum açma** **betiklerini** ve **GPO'ları** çalıştırır.

**explorer.exe**'yi başlatır.


## lsm.exe

**Yerel Oturum Yöneticisi**.\
smss.exe ile birlikte kullanıcı oturumlarını manipüle etmek için çalışır: Oturum açma/oturum kapatma, kabuk başlatma, masaüstünü kilitleme/açma vb.

W7'den sonra lsm.exe bir hizmete (lsm.dll) dönüştürüldü.

W7'de yalnızca 1 işlem olmalı ve bunlardan biri DLL çalıştıran bir hizmeti çalıştıran bir hizmet olmalıdır.


## services.exe

**Hizmet Denetim Yöneticisi**.\
**Otomatik başlatılan hizmetleri** ve **sürücüleri** yükler.

**svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** ve daha birçok işlemin ana işlemidir.

Hizmetler `HKLM\SYSTEM\CurrentControlSet\Services` içinde tanımlanır ve bu işlem, sc.exe tarafından sorgulanabilen hizmet bilgilerinin bellekteki bir veritabanını korur.

Dikkat edin, **bazı** **hizmetler** kendi **işlemlerinde çalışacak** ve diğerleri **svchost.exe işlemiyle paylaşacak**.

Yalnızca 1 işlem olmalıdır.


## lsass.exe

**Yerel Güvenlik Yetkilendirme Alt Sistemi**.\
Kullanıcı **kimlik doğrulama**sından ve **güvenlik** **jetonlarının** oluşturulmasından sorumludur. Kimlik doğrulama paketleri `HKLM\System\CurrentControlSet\Control\Lsa` konumunda bulunur.

**Güvenlik** **etkinlik** **günlüğüne** yazılır ve yalnızca 1 işlem olmalıdır.

Bu işlemin parolaları çalmak için yoğun bir şekilde saldırıya uğradığını unutmayın.


## svchost.exe

**Genel Hizmet Ana İşlemi**.\
Birleşik bir işlemde birden çok DLL hizmetini barındırır.

Genellikle **svchost.exe**'nin `-k` bayrağıyla başlatıldığını göreceksiniz. Bu, aynı işlemde başlatılacak hizmetleri içeren `-k` ile belirtilen bir anahtarın bulunacağı **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** kaydına bir sorgu başlatacaktır.

Örneğin: `-k UnistackSvcGroup` şunları başlatacaktır: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

**-s** bayrağı da bir argümanla birlikte kullanılıyorsa, svchost'un yalnızca bu argümandaki belirtilen hizmeti başlatması istenir.

Birkaç `svchost.exe` işlemi olacaktır. Bunlardan herhangi biri **`-k` bayrağı kullanmıyorsa**, bu çok şüphelidir. **services.exe'nin ebeveyn olmadığını** bulursanız, bu da çok şüphelidir.


## taskhost.exe

Bu işlem, DLL'lerden çalışan işlemler için bir ana bilgisayar görevi görür. Ayrıca DLL'lerden çalışan hizmetleri yükler.

W8'de bu taskhostex.exe olarak adlandırılır ve W10'da taskhostw.exe olarak adlandırılır.


## explorer.exe

Bu, kullanıcının masaüstünden sorumlu olan işlemdir ve dosya uzantıları aracılığıyla dosyaları başlatır.

**Giriş yapan her kullanıcı başına yalnızca 1** işlem oluşturulmalıdır.

Bu, sonlandırılması gereken **userinit.exe** tarafından çalıştırılır, bu nedenle bu işlem için **ebeveyn görünmemel
