# Bellek dökümü analizi

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong>!</summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **üzerinden paylaşın.**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **İspanya'daki en ilgili siber güvenlik etkinliği ve Avrupa'daki en önemlilerden biridir**. Teknik bilgiyi teşvik etme misyonuyla, bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## Başlangıç

Pcap içinde **zararlı yazılım** aramaya başlayın. [**Zararlı Yazılım Analizi**](../malware-analysis.md) bölümünde belirtilen **araçları** kullanın.

## [Volatility](volatility-cheatsheet.md)

**Volatility, bellek dökümü analizi için ana açık kaynak çerçevedir**. Bu Python aracı, dış kaynaklardan veya VMware VM'lerinden dökümleri analiz ederek, dökümün işletim sistemi profiline dayanarak işlemler ve şifreler gibi verileri tanımlar. Eklentilerle genişletilebilir, bu da onu adli incelemeler için son derece esnek hale getirir.

[**Burada bir hile sayfası bulun**](volatility-cheatsheet.md)

## Mini döküm çökme raporu

Döküm küçükse (birkaç KB, belki birkaç MB) o zaman muhtemelen bir mini döküm çökme raporu ve bellek dökümü değildir.

![](<../../../.gitbook/assets/image (529).png>)

Eğer Visual Studio yüklü ise, bu dosyayı açabilir ve işlem adı, mimari, istisna bilgisi ve yürütülen modüller gibi bazı temel bilgileri bağlayabilirsiniz:

![](<../../../.gitbook/assets/image (260).png>)

Ayrıca istisnayı yükleyebilir ve derlenmiş talimatları görebilirsiniz

![](<../../../.gitbook/assets/image (139).png>)

![](<../../../.gitbook/assets/image (607).png>)

Neyse ki, Visual Studio, dökümün derinlemesine analizini yapmak için en iyi araç değildir.

Derinlemesine incelemek için bunu **IDA** veya **Radare** kullanarak açmalısınız.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **İspanya'daki en ilgili siber güvenlik etkinliği ve Avrupa'daki en önemlilerden biridir**. Teknik bilgiyi teşvik etme misyonuyla, bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong>!</summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **üzerinden paylaşın.**

</details>
