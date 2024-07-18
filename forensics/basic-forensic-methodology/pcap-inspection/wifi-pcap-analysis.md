{% hint style="success" %}
AWS Hacking öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek hacking püf noktalarını paylaşın.

</details>
{% endhint %}

# BSSID'leri Kontrol Edin

WireShark kullanarak Wifi trafiğinin temel olduğu bir yakalama aldığınızda, yakalamadaki tüm SSID'leri araştırmaya başlayabilirsiniz: _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

O ekranın sütunlarından biri, **pcap içinde herhangi bir kimlik doğrulamasının bulunup bulunmadığını** gösterir. Eğer durum buysa, `aircrack-ng` kullanarak Brute Force deneyebilirsiniz:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
# Veri Paketlerinde / Yan Kanalda

Eğer **verinin bir Wifi ağı beacons içinde sızdırıldığını** şüpheleniyorsanız, ağın beacons'larını aşağıdaki gibi bir filtre kullanarak kontrol edebilirsiniz: `wlan contains <AĞINADI>`, veya `wlan.ssid == "AĞINADI"` filtrelenmiş paketler içinde şüpheli dizeler arayın.

# Bir Wifi Ağındaki Bilinmeyen MAC Adreslerini Bulma

Aşağıdaki bağlantı **bir Wifi Ağı içinde veri gönderen makineleri bulmak için** faydalı olacaktır:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Eğer zaten **MAC adreslerini biliyorsanız, çıktıdan onları çıkarabilirsiniz** ve aşağıdaki gibi kontroller ekleyebilirsiniz: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Bir kez **bilinmeyen MAC** adreslerini ağ içinde iletişim halinde tespit ettikten sonra, aşağıdaki gibi **filtreler** kullanabilirsiniz: `wlan.addr==<MAC adresi> && (ftp || http || ssh || telnet)` trafiğini filtrelemek için. Unutmayın ki ftp/http/ssh/telnet filtreleri trafiği şifrelediyseniz faydalı olacaktır.

# Trafik Şifrelemesi

Düzenle --> Tercihler --> Protokoller --> IEEE 802.11--> Düzenle

![](<../../../.gitbook/assets/image (426).png>)
