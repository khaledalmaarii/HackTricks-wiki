<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman seviyesine kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family) içerir
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **pull request** göndererek paylaşın.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmanıza ve değiştirmenize yardımcı olan kullanışlı bir programdır.\
İndirip çalıştırdığınızda, aracın nasıl kullanılacağına dair bir öğreticiyle karşılaşırsınız. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız, tamamlamanız şiddetle tavsiye edilir.

# Ne arıyorsunuz?

![](<../../.gitbook/assets/image (580).png>)

Bu araç, bir programın belleğinde **bazı değerlerin** (genellikle bir sayı) **nerede saklandığını** bulmak için çok kullanışlıdır.\
**Genellikle sayılar**, **4 bayt** şeklinde saklanır, ancak **double** veya **float** formatlarında da bulabilirsiniz veya bir sayıdan **farklı bir şey aramak** isteyebilirsiniz. Bu nedenle, ne aramak istediğinizi **seçtiğinizden** emin olmanız gerekir:

![](<../../.gitbook/assets/image (581).png>)

Ayrıca **farklı** türde **aramaları** belirtebilirsiniz:

![](<../../.gitbook/assets/image (582).png>)

Ayrıca, belleği tarama sırasında **oyunu durdurmak için** kutuyu işaretleyebilirsiniz:

![](<../../.gitbook/assets/image (584).png>)

## Kısayol Tuşları

_Edit --> Ayarlar --> Kısayol Tuşları_ bölümünde, **oyunu durdurma** gibi farklı amaçlar için farklı **kısayol tuşları** ayarlayabilirsiniz (belleği taramak istediğiniz bir noktada oldukça kullanışlıdır). Diğer seçenekler de mevcuttur:

![](<../../.gitbook/assets/image (583).png>)

# Değeri Değiştirme

Aranan değeri bulduktan sonra (bu konuda daha fazlası aşağıdaki adımlarda), değeri çift tıklayarak değiştirebilirsiniz, ardından değerin üzerine çift tıklayarak değeri değiştirebilirsiniz:

![](<../../.gitbook/assets/image (585).png>)

Ve son olarak, değişikliğin bellekte yapılmasını sağlamak için onay işaretini işaretleyin:

![](<../../.gitbook/assets/image (586).png>)

Bellekteki **değişiklik** hemen **uygulanır** (oyun bu değeri tekrar kullanana kadar değer **oyunda güncellenmez**).

# Değeri Arama

Öyleyse, kullanıcınızın hayatı gibi önemli bir değeri iyileştirmek istediğinizi ve bu değeri bellekte aradığınızı varsayalım)

## Bilinen bir değişiklikle

Değerin 100 olduğunu varsayalım, bu değeri aramak için bir tarama yaparsınız ve birçok eşleşme bulursunuz:

![](<../../.gitbook/assets/image (587).png>)

Sonra, değeri değiştirmek için bir şey yaparsınız ve oyunu durdurup bir sonraki taramayı yaparsınız:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine, **100'den yeni değere geçen değerleri** arayacaktır. Tebrikler, aradığınız değerin adresini buldunuz, şimdi onu değiştirebilirsiniz.\
_Eğer hala birkaç değeriniz varsa, o değeri tekrar değiştirmek için bir şey yapın ve adresleri filtrelemek için başka bir "sonraki tarama" yapın._

## Bilinmeyen Değer, bilinen değişiklik

Değeri **bilmediğiniz** ancak **nasıl değişeceğini** bildiğiniz bir senaryoda (ve hatta değişikliğin değerini de) sayınızı arayabilirsiniz.

Bu nedenle, "**Bilinmeyen başlangıç değeri**" türünde bir tarama yapmaya başlayın:

![](<../../.gitbook/assets/image (589).png>)

Ardından, değeri değiştirin, **değerin nasıl değiştiğini** belirtin (benim durumumda 1 azaldı) ve bir **sonraki tarama** yapın:

![](<../../.gitbook/assets/image (590).png>)

Seçilen şekilde değiştirilen **tüm değerler** size sunulacaktır:

![](<../../.gitbook/assets/image (591).png>)

Değerinizi bulduktan sonra, onu değiştirebilirsiniz.

Unutmayın, birçok olası değişiklik vardır ve sonuçları filtrelemek için bu adımları istediğiniz kadar yapabilirsiniz:

![](<../../.gitbook/assets/image (592).png>)

## Rastgele Bellek Adresi - Kodu Bulma

Şimdiye kadar bir değeri depolayan bir adresi nasıl bulacağımızı öğrendik, ancak **oyunun farklı çalıştırmalarında bu adresin belleğin farklı yerlerinde olması oldukça olasıdır**. Bu nedenle, her zaman o adresi nasıl bulacağımızı bulalım.

Bahsedilen hilelerden bazılarını kullanarak, mevcut oyununuzun önemli değeri depoladığı adresi bulun. Ardından (istediğinizde oyunu durdurarak) bulunan adrese **sağ tıklayın** ve "**Bu adresi kim kullanıyor**" veya "**Bu adrese yazanları bul**" seçeneğini seçin:

![](<../../.gitbook/assets/image (593).png>)

**İlk seçenek**, bu **adresi kullanan kod parçalarını** (oyunun kodunu değiştirebileceğiniz gibi başka şeyler için de kullanışlıdır) **bilmek** için kullanışlıdır.\
**İkinci seçenek**, daha **spesifik** ve bu durumda daha yardımcı olacaktır çünkü **bu değerin nereden yazıldığını** bilmek istiyoruz.

Bu seçeneklerden birini seçtikten sonra, **hata ayıklayıcı** program **programa bağlanacak** ve yeni bir **boş pencere** görünecektir. Şimdi, **oyunu oynayın** ve **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren adresleri** ile doldurulmalıdır:

![](<../../.gitbook/assets/image (594).png>)

Değeri değiştiren adresi bulduğunuzda, kodu **istediğiniz gibi değiştirebilirsiniz** (Cheat Engine, bunu hızlı bir şekilde NOP'larla değiştirmenize olanak tanır):

![](<../../.gitbook/assets/image (595).png>)

Artık kodu, sayınızı etkilemeyecek şekilde değiştirebilir veya her zaman olumlu bir şekilde etkileyecek şekilde değiştirebilirsiniz.
## Rastgele Bellek Adresi - İşaretçiyi Bulma

Önceki adımları takip ederek, ilgilendiğiniz değerin nerede olduğunu bulun. Ardından, "**Bu adrese yazan şeyi bulun**" kullanarak bu değeri yazan adresi bulun ve üzerine çift tıklayarak ayrıştırma görünümünü alın:

![](<../../.gitbook/assets/image (596).png>)

Ardından, yeni bir tarama yaparak "\[\]" arasındaki onaltılık değeri arayın (bu durumda $edx'in değeri):

![](<../../.gitbook/assets/image (597).png>)

(Eğer birkaç tane çıkarsa genellikle en küçük adres olanı gereklidir)\
Şimdi, ilgilendiğimiz değeri değiştirecek olan **işaretçiyi bulduk**.

"**Adresi El ile Ekle**" üzerine tıklayın:

![](<../../.gitbook/assets/image (598).png>)

Şimdi, "İşaretçi" onay kutusuna tıklayın ve bulunan adresi metin kutusuna ekleyin (bu senaryoda, önceki görüntüde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![](<../../.gitbook/assets/image (599).png>)

(İşaretçi adresini girdiğinizde ilk "Adres" otomatik olarak doldurulur)

Tamam'a tıklayın ve yeni bir işaretçi oluşturulacaktır:

![](<../../.gitbook/assets/image (600).png>)

Artık o değeri değiştirdiğinizde, **değerin bulunduğu bellek adresi farklı olsa bile önemli değeri değiştiriyorsunuz**.

## Kod Enjeksiyonu

Kod enjeksiyonu, hedef sürece bir kod parçası enjekte ettiğiniz ve ardından kodun yürütülmesini kendi yazdığınız kod üzerinden yönlendirdiğiniz bir tekniktir (örneğin, puanları azaltmak yerine puan vermek gibi).

Öyleyse, oyuncunuzun yaşamını 1 azaltan adresi bulduğunuzu hayal edin:

![](<../../.gitbook/assets/image (601).png>)

Ayrıştırıcıyı göstermek için Show disassembler üzerine tıklayın.\
Ardından, Auto assemble penceresini çağırmak için **CTRL+a** tuşlarına basın ve _**Template --> Code Injection**_ seçeneğini seçin.

![](<../../.gitbook/assets/image (602).png>)

Değiştirmek istediğiniz talimatın adresini doldurun (bu genellikle otomatik olarak doldurulur):

![](<../../.gitbook/assets/image (603).png>)

Bir şablon oluşturulacaktır:

![](<../../.gitbook/assets/image (604).png>)

Bu durumda, yeni montaj kodunu "**newmem**" bölümüne ekleyin ve orijinal kodu "**originalcode**" bölümünden kaldırın, eğer yürütülmesini istemiyorsanız. Bu örnekte, enjekte edilen kod 1 yerine 2 puan ekleyecektir:

![](<../../.gitbook/assets/image (605).png>)

**Execute üzerine tıklayın ve böylece kodunuz programda enjekte edilerek işlevin davranışı değişmelidir!**

# **Referanslar**

* **Cheat Engine öğretici, Cheat Engine ile başlamayı öğrenmek için tamamlayın**



<details>

<summary><strong>AWS hackleme hakkında sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>
