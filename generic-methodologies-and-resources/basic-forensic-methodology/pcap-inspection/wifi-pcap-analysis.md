# Wifi Pcap Analizi

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**]'yi (https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**]'i (https://opensea.io/collection/the-peass-family) içeren koleksiyonumuzu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## BSSID'leri Kontrol Edin

WireShark kullanarak Wifi trafiğinin ağırlıklı olduğu bir yakalama aldığınızda, yakalamadaki tüm SSID'leri incelemeye başlayabilirsiniz _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### Kaba Kuvvet

Bu ekranın sütunlarından biri, **pcap içinde herhangi bir kimlik doğrulaması bulunup bulunmadığını** gösterir. Eğer durum buysa, `aircrack-ng` kullanarak kaba kuvvet saldırısı yapabilirsiniz:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
## Veri Paketlerinde / Yan Kanalda

Eğer **verilerin bir Wifi ağı beacons'ları içinde sızdırıldığını** şüpheleniyorsanız, ağın beacons'larını aşağıdaki gibi bir filtre kullanarak kontrol edebilirsiniz: `wlan contains <AĞINADI>`, veya `wlan.ssid == "AĞINADI"` filtrelenmiş paketler içinde şüpheli dizgiler arayın.

## Bir Wifi Ağındaki Bilinmeyen MAC Adreslerini Bulma

Aşağıdaki bağlantı, **bir Wifi Ağı içinde veri gönderen makineleri bulmak için** faydalı olacaktır:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Eğer zaten **MAC adreslerini biliyorsanız, çıktıdan onları çıkarabilirsiniz** bu kontrolü ekleyerek: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Bir kez **bilinmeyen MAC** adreslerini ağ içinde iletişim halinde tespit ettiğinizde, şu gibi **filtreler** kullanabilirsiniz: `wlan.addr==<MAC adresi> && (ftp || http || ssh || telnet)` trafiğini filtrelemek için. Ftp/http/ssh/telnet filtrelerinin trafiği şifrelediyseniz faydalı olduğunu unutmayın.

## Trafik Şifrelemesi

Düzenle --> Tercihler --> Protokoller --> IEEE 802.11--> Düzenle

![](<../../../.gitbook/assets/image (499).png>)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
