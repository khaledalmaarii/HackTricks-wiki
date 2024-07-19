# Bellek dökümü analizi

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## Başlangıç

Pcap içinde **kötü amaçlı yazılım** için **arama yapmaya** başlayın. [**Kötü Amaçlı Yazılım Analizi**](../malware-analysis.md) bölümünde belirtilen **araçları** kullanın.

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility, bellek dökümü analizi için ana açık kaynak çerçevesidir**. Bu Python aracı, dış kaynaklardan veya VMware sanal makinelerinden dökümleri analiz eder, dökümün işletim sistemi profiline dayalı olarak süreçler ve şifreler gibi verileri tanımlar. Eklentilerle genişletilebilir, bu da onu adli soruşturmalar için son derece çok yönlü hale getirir.

**[Buradan bir ipucu sayfası bulun](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Mini döküm çökme raporu

Döküm küçükse (sadece birkaç KB, belki birkaç MB) muhtemelen bir mini döküm çökme raporudur ve bellek dökümü değildir.

![](<../../../.gitbook/assets/image (216).png>)

Visual Studio yüklüyse, bu dosyayı açabilir ve işlem adı, mimari, istisna bilgisi ve yürütülen modüller gibi bazı temel bilgileri bağlayabilirsiniz:

![](<../../../.gitbook/assets/image (217).png>)

Ayrıca istisnayı yükleyebilir ve decompile edilmiş talimatları görebilirsiniz.

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

Her neyse, Visual Studio, dökümün derinlemesine analizini yapmak için en iyi araç değildir.

Bunu **IDA** veya **Radare** kullanarak **derinlemesine** incelemelisiniz.
