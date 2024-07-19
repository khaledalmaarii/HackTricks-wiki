{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}


# Paketlenmiş ikili dosyaları tanımlama

* **string eksikliği**: Paketlenmiş ikili dosyalarda neredeyse hiç string bulmamak yaygındır.
* Birçok **kullanılmayan string**: Ayrıca, bir kötü amaçlı yazılım bazı ticari paketleyiciler kullanıyorsa, çapraz referanssız birçok string bulmak yaygındır. Bu stringler mevcut olsa bile, bu durum ikili dosyanın paketlenmediği anlamına gelmez.
* Bir ikili dosyayı paketlemek için hangi paketleyicinin kullanıldığını bulmaya çalışmak için bazı araçlar kullanabilirsiniz:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Temel Öneriler

* Paketlenmiş ikili dosyayı **IDA'da alttan başlayarak analiz etmeye** başlayın ve yukarı doğru ilerleyin. Unpackers, unpacked kod çıkış yaptığında çıkış yapar, bu nedenle unpacker'ın başlangıçta unpacked koda yürütme geçirmesi olası değildir.
* **register'lara** veya **bellek** **bölgelerine** **JMP** veya **CALL** arayın. Ayrıca, **argümanları ve bir adres yönlendirmesi iten fonksiyonlar arayın ve ardından `retn` çağırın**, çünkü bu durumda fonksiyonun dönüşü, çağrılmadan önce yığına itilen adresi çağırabilir.
* `VirtualAlloc` üzerinde bir **breakpoint** koyun, çünkü bu, programın unpacked kod yazabileceği bellek alanını ayırır. "Kullanıcı koduna çalıştır" veya fonksiyonu çalıştırdıktan sonra **EAX içindeki değere ulaşmak için F8** kullanın ve "**dump'taki o adresi takip edin**". Unpacked kodun kaydedileceği bölge olup olmadığını asla bilemezsiniz.
* **`VirtualAlloc`**'un "**40**" değerini argüman olarak alması, Okuma+Yazma+Çalıştırma anlamına gelir (buraya kopyalanacak bazı çalıştırılması gereken kod var).
* **Kodu unpack ederken**, **aritmetik işlemler** ve **`memcopy`** veya **`Virtual`**`Alloc` gibi fonksiyonlara **birçok çağrı** bulmak normaldir. Eğer yalnızca aritmetik işlemler gerçekleştiren ve belki de bazı `memcopy` yapan bir fonksiyonda bulursanız, öneri, **fonksiyonun sonunu bulmaya çalışmaktır** (belki bir JMP veya bazı register'lara çağrı) **veya** en azından **son fonksiyona çağrıya** kadar koşmak, çünkü kod ilginç değildir.
* Kodu unpack ederken, **bellek bölgesini değiştirdiğinizde** not alın, çünkü bir bellek bölgesi değişikliği **unpacking kodunun başlangıcını** gösterebilir. Process Hacker kullanarak bir bellek bölgesini kolayca dump edebilirsiniz (işlem --> özellikler --> bellek).
* Kodu unpack etmeye çalışırken, **zaten unpacked kodla çalışıp çalışmadığınızı bilmenin** iyi bir yolu, **ikili dosyanın stringlerini kontrol etmektir**. Eğer bir noktada bir atlama yaparsanız (belki bellek bölgesini değiştirerek) ve **çok daha fazla string eklendiğini** fark ederseniz, o zaman **unpacked kodla çalıştığınızı** bilebilirsiniz.\
Ancak, eğer paketleyici zaten birçok string içeriyorsa, "http" kelimesini içeren string sayısını görebilir ve bu sayının artıp artmadığını kontrol edebilirsiniz.
* Bir bellek bölgesinden bir yürütülebilir dosyayı dump ettiğinizde, bazı başlıkları [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) kullanarak düzeltebilirsiniz.
