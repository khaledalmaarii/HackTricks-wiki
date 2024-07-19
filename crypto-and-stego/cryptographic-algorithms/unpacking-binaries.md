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
{% endhint %}


# Paketlenmiş ikililerin tanımlanması

* **string eksikliği**: Paketlenmiş ikililerde neredeyse hiç string bulunmaması yaygındır.
* Birçok **kullanılmayan string**: Ayrıca, bir kötü amaçlı yazılım bazı ticari paketleyiciler kullanıyorsa, genellikle çapraz referansları olmayan birçok string bulmak yaygındır. Bu stringler mevcut olsa bile, bu durum ikilinin paketlenmediği anlamına gelmez.
* Bir ikilinin hangi paketleyici ile paketlendiğini bulmak için bazı araçlar kullanabilirsiniz:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Temel Öneriler

* Paketlenmiş ikiliyi **IDA'da alttan başlayarak analiz etmeye** başlayın ve yukarı doğru ilerleyin. Paket açıcılar, açılmış kod çıkınca çıkış yapar, bu nedenle paket açıcının açılmış koda başlangıçta yürütme geçirmesi olası değildir.
* **Kayıtlar** veya **bellek** **bölgelerine** **JMP** veya **CALL** arayın. Ayrıca, **argümanlar ve bir adres yönlendirmesi iten fonksiyonlar arayın ve ardından `retn` çağırın**, çünkü bu durumda fonksiyonun dönüşü, yığına itilen adresi çağırabilir.
* `VirtualAlloc` üzerinde bir **kesme noktası** koyun, çünkü bu, programın açılmış kod yazabileceği bellek alanını ayırır. "Kullanıcı koduna çalıştır" veya F8 kullanarak **fonksiyonu çalıştırdıktan sonra EAX içindeki değere ulaşın** ve "**dump'taki o adresi takip edin**". Açılmış kodun kaydedileceği bölge olup olmadığını asla bilemezsiniz.
* **`VirtualAlloc`**'un "**40**" değeri ile bir argüman olarak kullanılması, Okuma+Yazma+Çalıştırma anlamına gelir (buraya kopyalanacak bazı çalıştırma gerektiren kodlar olacak).
* **Kodu açarken**, **aritmetik işlemler** ve **`memcopy`** veya **`Virtual`**`Alloc` gibi fonksiyonlara **birçok çağrı** bulmak normaldir. Eğer yalnızca aritmetik işlemler gerçekleştiren ve belki de bazı `memcopy` yapan bir fonksiyonda bulursanız, öneri, **fonksiyonun sonunu bulmaya çalışmaktır** (belki bir JMP veya bazı kayıtlarla çağrı) **veya** en azından **son fonksiyona yapılan çağrıya kadar ilerleyin** çünkü kod ilginç değildir.
* Kodu açarken, **bellek bölgesini değiştirdiğinizde** not alın, çünkü bir bellek bölgesi değişikliği **açma kodunun başlangıcını** gösterebilir. Process Hacker kullanarak bir bellek bölgesini kolayca dökebilirsiniz (işlem --> özellikler --> bellek).
* Kodu açmaya çalışırken, **açılmış kodla çalışıp çalışmadığınızı bilmenin** iyi bir yolu, **ikili dosyanın stringlerini kontrol etmektir**. Eğer bir noktada bir atlama yaparsanız (belki bellek bölgesini değiştirerek) ve **çok daha fazla string eklendiğini** fark ederseniz, o zaman **açılmış kodla çalıştığınızı** bilebilirsiniz.\
Ancak, eğer paketleyici zaten birçok string içeriyorsa, "http" kelimesini içeren string sayısını görebilir ve bu sayının artıp artmadığını kontrol edebilirsiniz.
* Bir bellek bölgesinden bir yürütülebilir dosyayı dökerken, bazı başlıkları [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) kullanarak düzeltebilirsiniz.

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
</details>
{% endhint %}
