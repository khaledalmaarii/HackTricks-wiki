# macOS Güvenlik Korumaları

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## Gatekeeper

Gatekeeper genellikle **Karantina + Gatekeeper + XProtect** kombinasyonunu ifade etmek için kullanılır. Bu 3 macOS güvenlik modülü, **kullanıcıların potansiyel olarak zararlı yazılımları çalıştırmasını engellemeye çalışır**.

Daha fazla bilgi için:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## İşlem Sınırlayıcıları

### SIP - Sistem Bütünlük Koruması

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandbox, sandbox içinde çalışan uygulamaları, uygulamanın çalıştığı Sandbox profilinde belirtilen **izin verilen eylemlerle sınırlar**. Bu, uygulamanın **yalnızca beklenen kaynaklara erişeceğini** sağlamaya yardımcı olur.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Şeffaflık, Onay ve Kontrol**

**TCC (Şeffaflık, Onay ve Kontrol)** bir güvenlik çerçevesidir. Uygulamaların **izinlerini yönetmek** için tasarlanmıştır, özellikle hassas özelliklere erişimlerini düzenleyerek. Bu, **konum hizmetleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi unsurları içerir. TCC, uygulamaların bu özelliklere yalnızca açıkça kullanıcı onayı aldıktan sonra erişebilmesini sağlayarak, gizlilik ve kişisel veriler üzerinde kontrolü güçlendirir.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Başlatma/Çevre Kısıtlamaları ve Güven Önbelleği

MacOS'ta başlatma kısıtlamaları, bir işlemi başlatanın **kimin**, **nasıl** ve **nereden** başlatabileceğini tanımlayarak işlem başlatmayı düzenleyen bir güvenlik özelliğidir. macOS Ventura'da tanıtılan bir **güven önbelleği** içinde sistem ikili dosyalarını kısıtlama kategorilerine ayırır. Her yürütülebilir ikili dosya, **kendisi**, **ebeveyni** ve **sorumlu** kısıtlamaları için belirli **kurallara** sahiptir. macOS Sonoma'da üçüncü taraf uygulamalara **Çevre** Kısıtlamaları olarak genişletilen bu özellikler, işlem başlatma koşullarını düzenleyerek potansiyel sistem açıklarını azaltmaya yardımcı olur.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Zararlı Yazılım Kaldırma Aracı

Zararlı Yazılım Kaldırma Aracı (MRT), macOS'ın güvenlik altyapısının bir parçasıdır. Adından da anlaşılacağı gibi, MRT'nin temel işlevi, enfekte sistemlerden **bilinen zararlı yazılımları kaldırmaktır**.

Bir Mac'te zararlı yazılım tespit edildiğinde (XProtect veya başka bir yöntemle), MRT, zararlı yazılımı otomatik olarak **kaldırmak için kullanılabilir**. MRT sessizce arka planda çalışır ve genellikle sistem güncellendiğinde veya yeni bir zararlı yazılım tanımı indirildiğinde çalışır (zararlı yazılımı tespit etmek için MRT'nin kurallarının içinde olduğu gibi görünüyor).

XProtect ve MRT, macOS'ın güvenlik önlemlerinin bir parçası olsa da, farklı işlevlere sahiptir:

* **XProtect**, önleyici bir araçtır. İndirilen dosyaları (belirli uygulamalar aracılığıyla) **kontrol eder** ve bilinen herhangi bir zararlı yazılım türünü tespit ederse, dosyanın **açılmasını engeller**, böylece zararlı yazılımın sisteminize bulaşmasını önler.
* Öte yandan, **MRT**, tepkisel bir araçtır. Zararlı yazılım bir sisteme tespit edildikten sonra, hedef yazılımı temizlemek için çalışır.

MRT uygulaması **`/Library/Apple/System/Library/CoreServices/MRT.app`** konumundadır.

## Arka Plan Görevleri Yönetimi

**macOS**, artık bir aracın kod yürütmesini kalıcı hale getirmek için bilinen bir **teknik kullandığında her zaman uyarı verir** (örneğin, Giriş Öğeleri, Daemon'lar...), böylece kullanıcı **hangi yazılımın kalıcı olduğunu daha iyi bilir**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Bu, `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` konumunda bir **daemon** ve `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` konumunda bir **ajan** ile çalışır.

**`backgroundtaskmanagementd`**'nin bir kalıcı klasöre bir şeyin yüklendiğini bilmesinin yolu, **FSEvents**'leri alması ve bunlar için bazı **işleyiciler** oluşturmasıdır.

Ayrıca, Apple tarafından sık sık kalıcı olan **bilinen uygulamaları** içeren bir plist dosyası bulunur: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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
### Numaralandırma

Apple cli aracını kullanarak yapılandırılmış tüm arka plan öğelerini **numaralandırmak mümkündür**:
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
Bu bilgi **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** dosyasında saklanmaktadır ve Terminal FDA'ya ihtiyaç duyar.

### BTM ile Oynamak

Yeni bir kalıcılık bulunduğunda **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** türünde bir olay meydana gelir. Bu nedenle, bu olayın gönderilmesini veya ajanın kullanıcıyı uyarılmasını **engelleyen** herhangi bir yol, bir saldırganın BTM'yi _**atlamasına**_ yardımcı olacaktır.

* **Veritabanını sıfırlama**: Aşağıdaki komutu çalıştırmak veritabanını sıfırlayacak (temelden yeniden oluşturmalıdır), ancak bir şekilde, bu komutu çalıştırdıktan sonra **sistem yeniden başlatılana kadar yeni bir kalıcılık uyarılmayacaktır**.
* **root** yetkisi gereklidir.
```bash
# Reset the database
sfltool resettbtm
```
* **Ajanı Durdurun**: Yeni tespitler bulunduğunda kullanıcıya uyarı göndermeyecek şekilde ajanı durdurmak mümkündür.
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
* **Hata**: **Kalıcılığı oluşturan işlem hemen ardından hızlı bir şekilde sona ererse**, arka plan süreci onun hakkında bilgi almaya çalışacak, başarısız olacak ve yeni bir şeyin kalıcı olduğunu gösteren olayı gönderemeyecektir.

BTM hakkında daha fazla bilgi ve referanslar:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin</strong>!</summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) görün
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u takip edin.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
