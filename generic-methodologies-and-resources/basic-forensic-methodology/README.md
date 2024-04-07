# Temel Adli Bilişim Metodolojisi

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin**.
* **Hacking püf noktalarınızı göndererek [hacktricks deposuna](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud deposuna](https://github.com/carlospolop/hacktricks-cloud) PR gönderin**.

</details>

## Görüntü Oluşturma ve Bağlama

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md" %}
[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)
{% endcontent-ref %}

## Kötü Amaçlı Yazılım Analizi

Bu, **görüntüye sahip olduktan sonra yapılması zorunlu ilk adım değildir**. Ancak bir dosyanız, bir dosya sistemi görüntünüz, bellek görüntünüz, pcap'niz varsa bu kötü amaçlı yazılım analizi tekniklerini bağımsız olarak kullanabilirsiniz, bu nedenle bu eylemleri **akılda tutmak iyi olacaktır**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Görüntü İnceleme

Bir cihazın **adli görüntüsü** verildiğinde **bölümleri, kullanılan dosya sistemi** analiz etmeye ve potansiyel olarak **ilginç dosyaları kurtarmaya** başlayabilirsiniz (hatta silinmiş olanları). Nasıl yapılacağını öğrenin:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

Kullanılan işletim sistemlerine ve hatta platforma bağlı olarak farklı ilginç artefaktlar aranmalıdır:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## Belirli Dosya Türleri ve Yazılımın Detaylı İncelemesi

Çok **şüpheli bir dosyanız varsa**, o zaman **dosya türüne ve oluşturan yazılıma bağlı olarak** çeşitli **püf noktaları** faydalı olabilir.\
Bazı ilginç püf noktaları öğrenmek için aşağıdaki sayfayı okuyun:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

Özellikle şu sayfaya özel bir vurgu yapmak istiyorum:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## Bellek Dökümü İnceleme

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Pcap İnceleme

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **Anti-Adli Bilişim Teknikleri**

Mümkün olan **anti-adli bilişim tekniklerini** akılda tutun:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## Tehdit Avı

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% endcontent-ref %}

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin**.
* **Hacking püf noktalarınızı göndererek [hacktricks deposuna](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud deposuna](https://github.com/carlospolop/hacktricks-cloud) PR gönderin**.

</details>
