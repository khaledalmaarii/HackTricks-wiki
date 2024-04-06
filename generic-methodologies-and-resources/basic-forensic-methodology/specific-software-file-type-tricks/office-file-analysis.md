# Ofis dosyası analizi

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanarak dünyanın **en gelişmiş topluluk araçları** tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) kontrol edin. Bu sadece bir özet:

Microsoft birçok ofis belge formatı oluşturmuştur, iki ana türü **OLE formatları** (örneğin RTF, DOC, XLS, PPT) ve **Office Open XML (OOXML) formatları** (örneğin DOCX, XLSX, PPTX). Bu formatlar, içerisinde makrolar barındırabilir ve bu nedenle sıklıkla phishing ve kötü amaçlı yazılımların hedefi olabilir. OOXML dosyaları zip konteynerleri olarak yapılandırılmıştır, bu da dosyanın ve klasör hiyerarşisinin ve XML dosya içeriğinin açılmasına izin verir.

OOXML dosya yapılarını keşfetmek için belgeyi açma komutu ve çıktı yapısı verilmiştir. Bu dosyalara veri gizleme teknikleri belgelenmiş ve CTF zorluklarında veri gizleme konusunda devam eden yenilikler gösterilmiştir.

Analiz için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemek için kapsamlı araç setleri sunar. Bu araçlar, genellikle kötü amaçlı yazılım teslimatı için vektör olarak hizmet eden gömülü makroları tanımlamak ve analiz etmek konusunda yardımcı olur. VBA makrolarının analizi, Libre Office kullanılarak Microsoft Office olmadan yapılabilir, bu da kesme noktaları ve izleme değişkenleri ile hata ayıklamaya olanak tanır.

**oletools**'un kurulumu ve kullanımı basittir, pip ile kurulum için komutlar sağlanmış ve belgelerden makroların çıkarılması için komutlar verilmiştir. Makroların otomatik olarak çalıştırılması, genellikle ek kötü amaçlı yükler indirip çalıştıran `AutoOpen`, `AutoExec` veya `Document_Open` gibi işlevlerle tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışları** oluşturun ve kolayca çalıştırın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR'lar gönderin.

</details>
