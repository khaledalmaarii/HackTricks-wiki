# Bellek dökümü analizi

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**'ya PR göndererek paylaşın.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/), **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'nın en önemli etkinliklerinden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## Başlangıç

Pcap içinde **kötü amaçlı yazılım** aramaya başlayın. [**Kötü Amaçlı Yazılım Analizi**](../malware-analysis.md) bölümünde bahsedilen **araçları** kullanın.

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility, bellek dökümü analizi için ana kaynak kodlu bir çerçevedir**. Bu Python aracı, harici kaynaklardan veya VMware sanal makinelerinden dökümleri analiz ederek, dökümün işletim sistemi profiline dayanarak işlemler ve şifreler gibi verileri tanımlar. Eklentilerle genişletilebilir, bu da adli incelemeler için son derece esnek hale getirir.

**[İşte bir hile yaprağı](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)** bulun.

## Mini döküm çökme raporu

Döküm küçükse (sadece birkaç KB, belki birkaç MB), muhtemelen bir mini döküm çökme raporu ve bellek dökümü değildir.

![](<../../../.gitbook/assets/image (216).png>)

Visual Studio yüklü ise, bu dosyayı açabilir ve işlem adı, mimari, istisna bilgisi ve yürütülen modüller gibi bazı temel bilgileri bağlayabilirsiniz:

![](<../../../.gitbook/assets/image (217).png>)

Ayrıca istisnayı yükleyebilir ve dekompilasyon talimatlarını görebilirsiniz.

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

Neyse ki, Visual Studio, dökümün derinlik analizini yapmak için en iyi araç değildir.

Onu **IDA** veya **Radare** kullanarak derinlemesine inceleyebilirsiniz.
