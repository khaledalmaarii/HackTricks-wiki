# Tarayıcı Araçları

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı takip edin.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Tarayıcı Araçları <a href="#id-3def" id="id-3def"></a>

Tarayıcı araçları, web tarayıcıları tarafından depolanan çeşitli veri türlerini içerir. Bu araçlar, gezinme geçmişi, yer imleri ve önbellek verileri gibi verileri içeren işletim sistemi içindeki belirli klasörlerde saklanır. Tarayıcılara göre konum ve isim açısından farklılık gösterse de genellikle benzer veri türlerini depolarlar.

İşte en yaygın tarayıcı araçlarının özeti:

- **Gezinme Geçmişi**: Kullanıcının web sitelerini ziyaretlerini takip eder, kötü amaçlı sitelere yapılan ziyaretleri belirlemek için kullanışlıdır.
- **Otomatik Tamamlama Verileri**: Sık aramalara dayalı öneriler, gezinme geçmişiyle birleştirildiğinde bilgi sağlar.
- **Yer İmleri**: Kullanıcının hızlı erişim için kaydettiği siteler.
- **Eklentiler ve Ek Paketler**: Kullanıcı tarafından yüklenen tarayıcı eklentileri veya ek paketler.
- **Önbellek**: Web içeriğini (örneğin, resimler, JavaScript dosyaları) web sitesi yükleme sürelerini iyileştirmek için depolar, adli analiz için değerlidir.
- **Oturum Açma Bilgileri**: Kaydedilen oturum açma kimlik bilgileri.
- **Favikonlar**: Sekmelerde ve yer imlerinde görünen web siteleriyle ilişkilendirilen simgeler, kullanıcı ziyaretleri hakkında ek bilgi sağlar.
- **Tarayıcı Oturumları**: Açık tarayıcı oturumlarıyla ilgili veriler.
- **İndirmeler**: Tarayıcı aracılığıyla indirilen dosyaların kayıtları.
- **Form Verileri**: Web formlarına girilen bilgiler, gelecekteki otomatik tamamlama önerileri için kaydedilir.
- **Küçük Resimler**: Web sitelerinin önizleme görüntüleri.
- **Custom Dictionary.txt**: Kullanıcının tarayıcının sözlüğüne eklediği kelimeler.


## Firefox

Firefox, kullanıcı verilerini profiller içinde düzenler ve işletim sistemine bağlı olarak belirli konumlarda depolar:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Bu dizinlerdeki `profiles.ini` dosyası kullanıcı profillerini listeler. Her profilin verileri, `profiles.ini` dosyasının bulunduğu dizindeki `Path` değişkenine adı verilen bir klasörde depolanır. Bir profil klasörü eksikse, silinmiş olabilir.

Her profil klasörü içinde, birkaç önemli dosya bulunur:

- **places.sqlite**: Geçmiş, yer imleri ve indirmeleri depolar. Windows'ta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gibi araçlar geçmiş verilerine erişebilir.
- Geçmiş ve indirme bilgilerini çıkarmak için belirli SQL sorgularını kullanın.
- **bookmarkbackups**: Yer imi yedeklerini içerir.
- **formhistory.sqlite**: Web formu verilerini depolar.
- **handlers.json**: Protokol işleyicilerini yönetir.
- **persdict.dat**: Özel sözlük kelimeleri.
- **addons.json** ve **extensions.sqlite**: Yüklenen eklentiler ve ek paketler hakkında bilgi.
- **cookies.sqlite**: Çerez depolama, Windows'ta [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) ile incelenebilir.
- **cache2/entries** veya **startupCache**: Önbellek verileri, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) gibi araçlarla erişilebilir.
- **favicons.sqlite**: Favikonları depolar.
- **prefs.js**: Kullanıcı ayarları ve tercihleri.
- **downloads.sqlite**: Eski indirme veritabanı, şimdi places.sqlite'a entegre edilmiştir.
- **thumbnails**: Web sitesi küçük resimleri.
- **logins.json**: Şifreli oturum açma bilgileri.
- **key4.db** veya **key3.db**: Hassas bilgileri korumak için şifreleme anahtarlarını depolar.

Ek olarak, tarayıcının anti-phishing ayarlarını kontrol etmek için `prefs.js` dosyasında `browser.safebrowsing` girişlerini arayabilirsiniz. Bu girişler, güvenli gezinme özelliklerinin etkin veya devre dışı olup olmadığını gösterir.


Ana şifreyi çözmek için [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt) adresini kullanabilirsiniz.\
Aşağıdaki betik ve çağrı ile bir şifre dosyası belirterek brute force yapabilirsiniz:

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome, kullanıcı profillerini işletim sistemine bağlı olarak belirli konumlarda saklar:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Bu dizinlerde, kullanıcı verilerinin çoğu **Default/** veya **ChromeDefaultData/** klasörlerinde bulunabilir. Aşağıdaki dosyalar önemli verileri içerir:

- **History**: URL'leri, indirmeleri ve arama anahtar kelimelerini içerir. Windows'ta, geçmişi okumak için [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) kullanılabilir. "Transition Type" sütunu, kullanıcının bağlantılara tıklamaları, yazılan URL'ler, form gönderimleri ve sayfa yenilemeleri gibi çeşitli anlamlara sahiptir.
- **Cookies**: Çerezleri saklar. İncelemek için [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) kullanılabilir.
- **Cache**: Önbelleğe alınmış verileri saklar. Windows kullanıcıları, [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) aracını kullanabilir.
- **Bookmarks**: Kullanıcı yer imleri.
- **Web Data**: Form geçmişini içerir.
- **Favicons**: Web sitesi faviconlarını saklar.
- **Login Data**: Kullanıcı adları ve şifreler gibi giriş kimlik bilgilerini içerir.
- **Current Session**/**Current Tabs**: Geçerli gezinme oturumu ve açık sekmeler hakkında veriler.
- **Last Session**/**Last Tabs**: Chrome kapatılmadan önceki son oturumda aktif olan siteler hakkında bilgi.
- **Extensions**: Tarayıcı uzantıları ve eklentileri için dizinler.
- **Thumbnails**: Web sitesi küçük resimlerini saklar.
- **Preferences**: Eklentiler, uzantılar, açılır pencereler, bildirimler ve daha fazlası için ayarları içeren bilgi açısından zengin bir dosya.
- **Tarayıcının yerleşik anti-phishing özelliği**: Anti-phishing ve kötü amaçlı yazılım korumasının etkin olup olmadığını kontrol etmek için `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` komutunu çalıştırın. Çıktıda `{"enabled: true,"}` ifadesini arayın.


## **SQLite DB Veri Kurtarma**

Önceki bölümlerde gözlemleyebileceğiniz gibi, hem Chrome hem de Firefox verileri saklamak için **SQLite** veritabanlarını kullanır. Silinen girişleri kurtarmak mümkündür ve bunun için [**sqlparse**](https://github.com/padfoot999/sqlparse) **veya** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) aracı kullanılabilir.

## **Internet Explorer 11**

Internet Explorer 11, depolanan bilgileri ve ilgili ayrıntıları kolay erişim ve yönetim için çeşitli konumlarda yönetir.

### Metadata Depolama
Internet Explorer için metadata `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (VX V01, V16 veya V24 olabilir) dosyasında saklanır. Buna ek olarak, `V01.log` dosyası `WebcacheVX.data` ile değişiklik zamanı uyumsuzlukları gösterebilir, bu da `esentutl /r V01 /d` kullanarak onarım gerektiğini gösterir. Bu ESE veritabanında saklanan metadata, sırasıyla photorec ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi araçlar kullanılarak kurtarılabilir ve incelenebilir. **Containers** tablosu içinde, her veri segmentinin depolandığı belirli tabloları veya konteynerleri belirlemek mümkündür. Bu, Skype gibi diğer Microsoft araçları için önbellek ayrıntılarını içerir.

### Önbellek İnceleme
[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) aracı, önbelleği incelemek için kullanılır ve önbellek veri çıkarma klasör konumunu gerektirir. Önbellek için metadata, dosya adı, dizin, erişim sayısı, URL kaynağı ve önbellek oluşturma, erişim, değiştirme ve sona erme zamanlarını gösteren zaman damgalarını içerir.

### Çerez Yönetimi
Çerezler [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) kullanılarak incelenebilir ve metadata, isimler, URL'ler, erişim sayıları ve çeşitli zamanla ilgili ayrıntıları içerir. Kalıcı çerezler `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` dizininde saklanırken, oturum çerezleri bellekte bulunur.

### İndirme Ayrıntıları
İndirme metadata'sı [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) aracıyla erişilebilir ve belirli konteynerler, URL, dosya türü ve indirme konumu gibi verileri içerir. Fiziksel dosyalar `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` altında bulunabilir.

### Gezinti Geçmişi
Gezinti geçmişini incelemek için [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kullanılabilir. Bu, çıkarılan geçmiş dosyalarının konumunu ve Internet Explorer için yapılandırmayı gerektirir. Buradaki metadata, değiştirme ve erişim zamanları ile erişim sayılarını içerir. Geçmiş dosyaları `%userprofile%\Appdata\Local\Microsoft\Windows\History` dizininde bulunur.

### Yazılan URL'ler
Yazılan URL'ler ve kullanım zamanları, `NTUSER.DAT` altında `Software\Microsoft\InternetExplorer\TypedURLs` ve `Software\Microsoft\InternetExplorer\TypedURLsTime` altında kaydedilir. Bu, kullanıcının girdiği son 50 URL'yi ve son giriş zamanlarını takip eder.

## Microsoft Edge

Microsoft Edge, kullanıcı verilerini `%userprofile%\Appdata\Local\Packages` dizininde saklar. Farklı veri türleri için yol şunlardır:

- **Profil Yolu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Geçmiş, Çerezler ve İndirmeler**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ayarlar, Yer İmleri ve Okuma Listesi**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Önbellek**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Son Etkin Oturumlar**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari verileri `/Users/$User/Library/Safari` dizin
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni alın.
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu.
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
