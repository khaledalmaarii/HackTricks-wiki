# Temel Adli Bilişim Metodolojisi

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter'da** takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** göndererek paylaşın.

</details>

## Bir Görüntü Oluşturma ve Bağlama

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md" %}
[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)
{% endcontent-ref %}

## Zararlı Yazılım Analizi

Bu, **görüntüye sahip olduktan sonra yapılması gereken ilk adım olmayabilir**. Ancak bir dosyanız, bir dosya sistemi görüntüsü, bellek görüntüsü, pcap... varsa bu zararlı yazılım analizi tekniklerini bağımsız olarak kullanabilirsiniz, bu yüzden bu eylemleri **akılda tutmak iyi olur**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Bir Görüntünün İncelenmesi

Eğer size bir cihazın **adli görüntüsü** verilirse, **bölümleri, kullanılan dosya sistemi** ni analiz etmeye ve potansiyel olarak **ilginç dosyaları** (hatta silinmiş olanları) **kurtarmaya** başlayabilirsiniz. Nasıl yapılacağını öğrenin:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

Kullanılan işletim sistemlerine ve hatta platforma bağlı olarak farklı ilginç bulgular aranmalıdır:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## Belirli Dosya Türlerinin ve Yazılımların Derin İncelemesi

Eğer çok **şüpheli bir dosyanız** varsa, o zaman **dosya türüne ve oluşturan yazılıma** bağlı olarak birkaç **hile** işe yarayabilir. İlginç hileler öğrenmek için aşağıdaki sayfayı okuyun:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

Özellikle şu sayfaya özel bir bahsetmek istiyorum:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## Bellek Dökümü İncelemesi

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Pcap İncelemesi

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **Anti-Adli Bilişim Teknikleri**

Mümkün olan anti-adli bilişim tekniklerinin kullanımını akılda tutun:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## Tehdit Avı

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% endcontent-ref %}

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter'da** takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** göndererek paylaşın.

</details>
