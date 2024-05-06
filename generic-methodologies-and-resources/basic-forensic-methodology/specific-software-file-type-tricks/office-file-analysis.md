# Ofis dosyası analizi

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) kullanarak dünyanın **en gelişmiş** topluluk araçları tarafından desteklenen ve **iş akışlarını otomatikleştirmeyi** kolayca sağlayın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresine bakın. Bu sadece bir özet:

Microsoft birçok ofis belge formatı oluşturmuştur, iki ana türü **OLE formatları** (örneğin RTF, DOC, XLS, PPT) ve **Office Open XML (OOXML) formatları** (örneğin DOCX, XLSX, PPTX) olarak adlandırılır. Bu formatlar, içerisinde makrolar barındırabilir ve bu nedenle phishing ve kötü amaçlı yazılımlar için hedef olabilir. OOXML dosyaları zip konteynerleri olarak yapılandırılmıştır, bu da dosya ve klasör hiyerarşisini ve XML dosya içeriğini açığa çıkararak incelemeye olanak tanır.

OOXML dosya yapılarını keşfetmek için belgeyi açmak ve çıktı yapısını görmek için komutlar verilmiştir. Bu dosyalara veri gizleme teknikleri belgelenmiştir ve CTF zorluklarında veri gizleme konusunda sürekli yenilikler olduğunu göstermektedir.

Analiz için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemek için kapsamlı araç setleri sunar. Bu araçlar, genellikle kötü amaçlı yazılım teslimatı için vektör olarak hizmet eden gömülü makroları tanımlamak ve analiz etmek konusunda yardımcı olur. VBA makrolarının analizi, Libre Office kullanılarak Microsoft Office olmadan yapılabilir, bu da kesme noktaları ve izleme değişkenleri ile hata ayıklamaya olanak tanır.

**oletools**'un kurulumu ve kullanımı basittir, pip aracılığıyla kurulum için komutlar sağlanmıştır ve belgelerden makroları çıkarmak için kullanılır. Makroların otomatik olarak çalıştırılması, `AutoOpen`, `AutoExec` veya `Document_Open` gibi işlevlerle tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **iş akışlarını otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

<details>

<summary><strong>Sıfırdan kahramana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github depolarına PR göndererek paylaşın.**

</details>
