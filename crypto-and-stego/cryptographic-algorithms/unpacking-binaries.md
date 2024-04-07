<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR gönderin.

</details>


# Paketlenmiş ikili dosyaları tanımlama

* **Dize eksikliği**: Paketlenmiş ikili dosyaların neredeyse hiç dize içermediği yaygındır
* **Kullanılmayan çok sayıda dize**: Ayrıca, bir kötü amaçlı yazılımın ticari bir paketleyici kullandığında çok sayıda çapraz referans olmayan dize bulmak yaygındır. Bu dizeler varsa bile, bu ikili dosyanın paketlenmediği anlamına gelmez.
* Bir ikili dosyanın hangi paketleyicinin kullanıldığını bulmaya çalışmak için bazı araçlar da kullanabilirsiniz:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Temel Tavsiyeler

* Paketlenmiş ikili dosyayı **IDA'da alttan yukarı doğru analiz etmeye başlayın ve yukarı doğru hareket edin**. Paketleyici, paketlenmiş kodun çıkış yaptığı anda çıkar, bu nedenle paketleyicinin başlangıçta paketlenmiş kodun yürütülmesini paketlenmiş kodun yürütülmesine geçirme olasılığı düşüktür.
* **JMP'leri** veya **CALL'ları** araştırın, **kayıtlara** veya **bellek bölgelerine** yönlendirin. Ayrıca, **argümanları iten işlevleri ve bir adres yönü ve ardından `retn` çağıran işlevleri arayın**, çünkü bu durumda işlevin dönüşü, çağrılan adresi yığın üzerine ittikten sonra çağırmadan önce çağırabilir.
* `VirtualAlloc` üzerine bir **kesme noktası** koyun, çünkü bu, programın yazılabileceği bellek alanını ayırır. Fonksiyonu çalıştırdıktan sonra EAX içindeki değere ulaşmak için "kullanıcı koduna çalış" veya F8'i kullanın ve "bu adrese dökün". Paketlenmiş kodun kaydedileceği bölge olup olmadığını asla bilemezsiniz.
* Argüman olarak "**40**" değeriyle **`VirtualAlloc`** kullanmak, Oku+Yaz+Çalıştır anlamına gelir (buraya kopyalanacak bir yürütme gerektiren kod).
* Kodu açarken, **aritmetik işlemlere** ve **`memcopy`** veya **`Virtual`**`Alloc` gibi işlevlere **çok sayıda çağrı** bulmak normaldir. Yalnızca aritmetik işlemler gerçekleştiren ve belki de bazı `memcopy` işlemleri gerçekleştiren bir işlevde bulunursanız, işlevin sonunu (belki bir JMP veya bir kayda çağrı) **bulmaya çalışın** veya en azından **son işlevi çağıran çağrıyı bulun** ve kod ilginç değilse çalıştırın.
* Kodu açarken, bir bellek bölgesini değiştirdiğinizde **bellek bölgesi değişikliğinin paketlenmiş kodun başlangıcını gösterebileceğini** unutmayın. Bir bellek bölgesini Process Hacker (işlem --> özellikler --> bellek) kullanarak kolayca dökümleyebilirsiniz.
* Kodu açmaya çalışırken, **zaten paketlenmemiş kodla çalışıp çalışmadığınızı bilmek** (böylece sadece dökebilirsiniz) için ikili dosyanın dizelerini kontrol etmek iyi bir yoldur. Bir noktada bir sıçrama yaparsanız (belki bellek bölgesini değiştirirken) ve **daha fazla dize eklendiğini fark ederseniz**, o zaman **paketlenmemiş kodla çalıştığınızı** bilebilirsiniz.\
Ancak, paketleyicide zaten çok sayıda dize bulunuyorsa, "http" kelimesini içeren dize sayısına bakabilir ve bu sayının artıp artmadığını görebilirsiniz.
* Bir bellek bölgesinden bir yürütülebilir dosyayı döktüğünüzde, bazı başlıkları [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) kullanarak düzeltebilirsiniz.


<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR gönderin.

</details>
