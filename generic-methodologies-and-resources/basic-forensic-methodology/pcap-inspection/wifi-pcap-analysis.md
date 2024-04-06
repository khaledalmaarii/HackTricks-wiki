<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>


# BSSID'leri Kontrol Et

WireShark kullanarak Wifi trafiğinin olduğu bir yakalamayı aldığınızda, yakalamadaki tüm SSID'leri araştırmaya başlayabilirsiniz: _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Bu ekranın sütunlarından biri, yakalamada **herhangi bir kimlik doğrulama bulunup bulunmadığını** gösterir. Eğer durum buysa, `aircrack-ng` kullanarak Brute Force deneyebilirsiniz:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Örneğin, daha sonra trafiği şifrelemek için gereken bir PSK'yı (pre shared-key) koruyan WPA parolasını alacaktır.

# Beacon / Yan Kanal Verileri

Eğer **bir Wifi ağındaki verilerin beaconlarda sızdırıldığını** düşünüyorsanız, ağın beaconlarını aşağıdaki gibi bir filtreyi kullanarak kontrol edebilirsiniz: `wlan contains <AĞINADI>`, veya `wlan.ssid == "AĞINADI"` filtrelenmiş paketler içinde şüpheli dizeleri arayın.

# Bilinmeyen MAC Adreslerini Bir Wifi Ağından Bulma

Aşağıdaki bağlantı, **bir Wifi Ağı içinde veri gönderen makineleri bulmak** için faydalı olacaktır:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Eğer **MAC adreslerini zaten biliyorsanız, çıktıdan çıkarabilirsiniz** ve şu gibi kontroller ekleyebilirsiniz: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Ağ içinde iletişim kuran **bilinmeyen MAC** adreslerini tespit ettikten sonra, trafiğini filtrelemek için aşağıdaki gibi **filtreler** kullanabilirsiniz: `wlan.addr==<MAC adresi> && (ftp || http || ssh || telnet)`. Unutmayın ki ftp/http/ssh/telnet filtreleri, trafiği şifre çözdüyseniz faydalı olacaktır.

# Trafik Şifrelemek

Düzenle --> Tercihler --> Protokoller --> IEEE 802.11--> Düzenle

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
