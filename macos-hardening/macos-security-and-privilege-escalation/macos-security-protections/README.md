# macOS Güvenlik Korumaları

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Gatekeeper

Gatekeeper genellikle **Karantina + Gatekeeper + XProtect** kombinasyonuna atıfta bulunmak için kullanılır, bu 3 macOS güvenlik modülü, **kullanıcıların potansiyel olarak zararlı yazılımları çalıştırmasını engellemeye çalışacaktır**.

Daha fazla bilgi için:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## İşlem Sınırlayıcılar

### SIP - Sistem Bütünlüğü Koruması

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Kum Havuzu

MacOS Kum Havuzu, **kum havuzu profili ile çalışan uygulamaların yalnızca beklenen kaynaklara erişeceğinden emin olur**, bu da **uygulamanın yalnızca izin verilen eylemleri gerçekleştireceğini** sağlar.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Şeffaflık, Onay ve Kontrol**

**TCC (Şeffaflık, Onay ve Kontrol)** bir güvenlik çerçevesidir. Uygulamaların izinlerini yönetmek için tasarlanmıştır, özellikle hassas özelliklere erişimlerini düzenleyerek. Bu, **konum hizmetleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi unsurları içerir. TCC, uygulamaların bu özelliklere yalnızca açık kullanıcı onayı aldıktan sonra erişebilmelerini sağlar, böylece gizliliği ve kişisel veriler üzerinde kontrolü güçlendirir.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Başlatma/Çevre Kısıtlamaları ve Güven Önbelleği

MacOS'taki Başlatma kısıtlamaları, bir işlemi başlatmayı düzenleyen bir güvenlik özelliğidir, bir işlemi **kimin**, **nasıl** ve **nereden** başlatabileceğini tanımlayarak. macOS Ventura'da tanıtılan bir **güven önbelleği** içinde sistem ikili dosyalarını kısıtlama kategorilerine ayırır. Her yürütülebilir ikili dosya için başlatma kuralları belirlenir, **kendisi**, **ebeveyni** ve **sorumlu** kısıtlamaları dahil. macOS Sonoma'da üçüncü taraf uygulamalar için **Çevre** Kısıtlamaları olarak genişletilen bu özellikler, işlem başlatma koşullarını yöneterek potansiyel sistem açıklarını azaltmaya yardımcı olur.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Zararlı Yazılım Kaldırma Aracı

Zararlı Yazılım Kaldırma Aracı (MRT), macOS'ın güvenlik altyapısının bir parçasıdır. Adından da anlaşılacağı gibi, MRT'nin temel işlevi, **enfekte sistemlerden bilinen zararlı yazılımları kaldırmaktır**.

Bir Mac'te zararlı yazılım tespit edildiğinde (XProtect tarafından veya başka bir şekilde), MRT otomatik olarak **zararlı yazılımı kaldırmak** için kullanılabilir. MRT genellikle arka planda sessizce çalışır ve genellikle sistem güncellendiğinde veya yeni bir zararlı yazılım tanımı indirildiğinde çalışır (zararlı yazılımı tespit etmek için MRT'nin kurallarının uygulandığı gibi görünüyor).

XProtect ve MRT, macOS'ın güvenlik önlemlerinin bir parçası olsalar da, farklı işlevleri yerine getirirler:

* **XProtect**, bir önleyici araçtır. **Dosyaları indirildikçe** (belirli uygulamalar aracılığıyla) kontrol eder ve bilinen herhangi bir tür zararlı yazılım tespit ederse, dosyanın **açılmasını engeller**, böylece zararlı yazılımın sisteminize bulaşmasını engeller.
* **MRT** ise **reaktif bir araçtır**. Sistemde zararlı yazılım tespit edildikten sonra çalışır ve sistemi temizlemek için suçlu yazılımı kaldırmayı hedefler.

MRT uygulaması **`/Library/Apple/System/Library/CoreServices/MRT.app`** konumundadır.

## Arka Plan Görevleri Yönetimi

**macOS**, artık bir aracın kod yürütmesini sürdürmek için bilinen bir **teknik kullandığında her zaman uyarır** (örneğin, Giriş Öğeleri, Daemonlar...), böylece kullanıcı daha iyi **hangi yazılımın sürekli olduğunu bilir**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Bu, `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` konumunda bulunan bir **daemon** ile çalışır ve `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` konumunda bir **ajan** içerir.

**`backgroundtaskmanagementd`**'nin bir şeyin sürekli bir klasöre yüklendiğini bilmesinin yolu, **FSEvents**'leri alması ve bunlar için bazı **işleyiciler** oluşturmasıdır.

Ayrıca, Apple tarafından sık ​​sık sürekli olan **tanınmış uygulamaları** içeren bir plist dosyası bulunur: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Sıralama

Apple cli aracını çalıştırarak yapılandırılmış tüm arka plan öğelerini **sıralamak mümkündür**:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ayrıca, bu bilgileri [**DumpBTM**](https://github.com/objective-see/DumpBTM) ile de listeleyebilirsiniz.
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Bu bilgi **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** içinde depolanmaktadır ve Terminal'in FDA'ya ihtiyacı vardır.

### BTM ile Oynama

Yeni bir kalıcılık bulunduğunda **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** türünde bir olay meydana gelir. Dolayısıyla, bu **olayın** gönderilmesini veya **ajanın kullanıcıyı uyarısını engellemenin** bir yolu bir saldırganın BTM'yi _atlamasına_ yardımcı olacaktır.

* **Veritabanını sıfırlama**: Aşağıdaki komutu çalıştırmak veritabanını sıfırlayacaktır (temelden yeniden oluşturmalıdır), ancak bu komutu çalıştırdıktan sonra **sistem yeniden başlatılana kadar yeni kalıcılıklar uyarılmayacaktır**.
* **root** yetkisi gereklidir.
```bash
# Reset the database
sfltool resettbtm
```
* **Ajanı Durdurun**: Ajan'a durdurma sinyali göndermek mümkündür, böylece yeni tespitler bulunduğunda kullanıcıya uyarı vermez.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Hata**: Eğer **kalıcılığı oluşturan işlem hemen ardından hızlı bir şekilde sona ererse**, daemon onun hakkında **bilgi almaya çalışacak**, **başarısız olacak** ve yeni bir şeyin kalıcı olduğunu gösteren olayı gönderemeyecek.

Referanslar ve **BTM hakkında daha fazla bilgi**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
