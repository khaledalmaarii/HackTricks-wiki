# Ofis dosyası analizi

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanarak dünyanın **en gelişmiş topluluk araçları** tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresini kontrol edin. Bu sadece bir özet:

Microsoft birçok ofis belge formatı oluşturmuştur, iki ana türü **OLE formatları** (örneğin RTF, DOC, XLS, PPT) ve **Office Open XML (OOXML) formatları** (örneğin DOCX, XLSX, PPTX). Bu formatlar makrolar içerebilir, bu nedenle balık avı ve kötü amaçlı yazılımlar için hedef olabilirler. OOXML dosyaları zip konteynerleri olarak yapılandırılmıştır, bu da açılarak inceleme yapılmasına izin verir, dosya ve klasör hiyerarşisini ve XML dosya içeriğini ortaya çıkarır.

OOXML dosya yapılarını keşfetmek için belgeyi açmak ve çıktı yapısını gösteren komut verilmiştir. Bu dosyalara veri gizleme teknikleri belgelenmiştir, bu da CTF zorluklarında veri gizleme konusunda devam eden yenilikleri gösterir.

Analiz için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemek için kapsamlı araç setleri sunar. Bu araçlar, genellikle kötü amaçlı yazılım teslimat vektörleri olarak hizmet eden gömülü makroları tanımlamak ve analiz etmek konusunda yardımcı olur, genellikle ek kötü amaçlı yükleri indirip yürüten kötü amaçlı yazılımlar için. VBA makrolarının analizi, Libre Office kullanılarak Microsoft Office olmadan yapılabilir, bu da kesme noktaları ve izleme değişkenleri ile hata ayıklamaya izin verir.

**oletools**'un kurulumu ve kullanımı basittir, pip ile kurulum için komutlar sağlanmıştır ve belgelerden makroları çıkarmak için kullanılır. Makroların otomatik olarak yürütülmesi, `AutoOpen`, `AutoExec` veya `Document_Open` gibi işlevlerle tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **otomatik iş akışları** oluşturun ve kolayca çalıştırın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
