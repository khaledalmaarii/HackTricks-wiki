<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin.
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# Paketlenmiş ikili dosyaları tanımlama

* **Dize eksikliği**: Paketlenmiş ikili dosyalarda neredeyse hiç dize bulunmadığı sıkça görülür.
* Birçok **kullanılmayan dize**: Ayrıca, bir kötü amaçlı yazılımın ticari bir paketleme aracı kullandığı durumlarda, çapraz referans olmayan birçok dize bulmak yaygındır. Bu dizelerin var olması, ikili dosyanın paketlenmediği anlamına gelmez.
* Bir ikili dosyanın hangi paketleyicinin kullanıldığını bulmak için bazı araçlar da kullanabilirsiniz:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Temel Öneriler

* Paketlenmiş ikili dosyayı analiz etmeye başlamak için IDA'da alttan yukarı doğru hareket etmek en iyisidir. Paketleyici, açılmış kod çıkış yaptığında unpacker da çıkış yapar, bu yüzden unpacker'ın başlangıçta açılmış kodun yürütmesine geçmesi olası değildir.
* **JMP'leri** veya **CALL'ları** **registerlara** veya **bellek bölgelerine** arayın. Ayrıca, argümanları iten ve bir adres yönüne çağrı yapan **fonksiyonları** arayın ve ardından `retn` çağrısı yapın, çünkü bu durumda fonksiyonun dönüşü, çağrılmadan önce yığıta itilen adresi çağırabilir.
* `VirtualAlloc` üzerine bir **kesme noktası** koyun, çünkü bu, programın açılmış kodu yazabileceği bellekte yer ayırır. Fonksiyonu çalıştırdıktan sonra EAX içindeki değere ulaşmak için "kullanıcı koduna çalış" veya F8'i kullanarak "**dökümdeki o adrese gidin**". Açılmış kodun kaydedileceği bölge olup olmadığını asla bilemezsiniz.
* **`VirtualAlloc`** ile "**40**" değeri bir argüman olarak kullanıldığında, Oku+Yaz+Çalıştır anlamına gelir (buraya yürütme gerektiren bazı kodlar kopyalanacak).
* Kodu açarken, genellikle **birçok aritmetik işlem** ve **`memcopy`** veya **`VirtualAlloc`** gibi fonksiyonlara yapılan **birçok çağrı** bulunur. Yalnızca aritmetik işlemler gerçekleştiren ve belki de bazı `memcopy` işlemleri yapan bir fonksiyonda bulunuyorsanız, öneri, fonksiyonun sonunu (belki bir JMP veya bir kayda çağrı) **bulmaya çalışmak** veya en azından **son fonksiyona yapılan çağrıyı bulmak** ve ona kadar çalıştırmaktır, çünkü kod ilginç değildir.
* Kodu açarken, bir bellek bölgesini değiştirdiğinizde **bellek bölgesi değişikliğini** not edin, çünkü bellek bölgesi değişikliği, açılmış kodun başlangıcını gösterebilir. Bir bellek bölgesini Process Hacker kullanarak kolayca dökümleyebilirsiniz (process --> properties --> memory).
* Kodu açmaya çalışırken, bir ikili dosyanın dizelerini kontrol ederek **zaten açılmış kodla çalışıp çalışmadığınızı** (bu durumda sadece dökümleyebilirsiniz) iyi bir şekilde anlayabilirsiniz. Bir noktada bir sıçrama yaparsanız (bellek bölgesini değiştirerek olabilir) ve **daha fazla dize eklendiğini fark ederseniz**, o zaman **açılmış kodla çalıştığınızı** bilebilirsiniz.\
Ancak, eğer paketleyicide zaten birçok dize bulunuyorsa, "http" kelimesini içeren dize sayısını görebilir ve bu sayının artıp artmadığını kontrol edebilirsiniz.
* Bir bellek bölgesinden bir yürütülebilir dökümlediğinizde, bazı başlıkları düzeltmek için [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) kullanabilirsiniz.


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin.
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
