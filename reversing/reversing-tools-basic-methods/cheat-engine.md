# Hile Motoru

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* 💬 **Discord grubuna** katılın](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u takip edin.
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>

[**Hile Motoru**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmanıza ve değiştirmenize olanak tanıyan faydalı bir programdır.\
İndirip çalıştırdığınızda, aracı nasıl kullanacağınıza dair bir öğreticiyle karşılaşırsınız. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız, öğreticiyi tamamlamanız şiddetle tavsiye edilir.

## Ne arıyorsunuz?

![](<../../.gitbook/assets/image (759).png>)

Bu araç, bir programın belleğinde **bazı değerlerin** (genellikle bir sayı) **nerede saklandığını** bulmak için çok faydalıdır.\
Genellikle sayılar **4 bayt** formunda saklanır, ancak bunları **double** veya **float** formatlarında da bulabilir veya bir sayıdan **farklı bir şey aramak** isteyebilirsiniz. Bu nedenle, aramak istediğiniz şeyi **seçtiğinizden emin olmanız gerekir**:

![](<../../.gitbook/assets/image (321).png>)

Ayrıca **farklı türlerde aramaları** belirtebilirsiniz:

![](<../../.gitbook/assets/image (307).png>)

Ayrıca, **belleği tarama sırasında oyunu durdurmak** için kutuyu işaretleyebilirsiniz:

![](<../../.gitbook/assets/image (1049).png>)

### Kısayol Tuşları

_**Düzen --> Ayarlar --> Kısayol Tuşları**_ bölümünde, **oyunu durdurmak** gibi farklı amaçlar için farklı **kısayol tuşları** ayarlayabilirsiniz (bunu belleği taramak istediğiniz bir noktada oldukça faydalıdır). Diğer seçenekler de mevcuttur:

![](<../../.gitbook/assets/image (861).png>)

## Değeri Değiştirme

Bir kez **aramakta olduğunuz değerin** nerede olduğunu **bulduğunuzda** (bu konuyla ilgili daha fazlası aşağıdaki adımlarda) değeri değiştirebilirsiniz, değere çift tıklayarak değeri çift tıklayarak değiştirebilirsiniz:

![](<../../.gitbook/assets/image (560).png>)

Ve son olarak, bellekteki değişikliği yapmak için işareti işaretleyin:

![](<../../.gitbook/assets/image (382).png>)

**Bellekteki değişiklik** hemen **uygulanacaktır** (oyun bu değeri tekrar kullanana kadar değer **oyunda güncellenmeyecektir**).

## Değeri Arama

Öyleyse, kullanıcı hayatı gibi önemli bir değeri (örneğin) iyileştirmek istediğinizi ve bu değeri bellekte aradığınızı varsayalım)

### Bilinen bir değişiklik aracılığıyla

Değerin 100 olduğunu arıyorsanız, bu değeri aramak için bir tarama yaparsınız ve birçok eşleşme bulursunuz:

![](<../../.gitbook/assets/image (105).png>)

Sonra, **değerin değiştiği bir şey yaparsınız**, oyunu **durdurursunuz** ve **bir sonraki taramayı yaparsınız**:

![](<../../.gitbook/assets/image (681).png>)

Cheat Engine, **100'den yeni değere geçen değerleri** arayacaktır. Tebrikler, aradığınız değerin **adresini buldunuz**, şimdi onu değiştirebilirsiniz.\
_Eğer hala birkaç değerin varsa, o değeri tekrar değiştirmek için bir şey yapın ve adresleri filtrelemek için başka bir "sonraki tarama" yapın._

### Bilinmeyen Değer, bilinen değişiklik

Değeri **bilmiyorsanız** ancak **nasıl değişeceğini** biliyorsanız (ve hatta değişikliğin değerini biliyorsanız) sayınızı arayabilirsiniz.

Bu nedenle, "**Bilinmeyen başlangıç değeri**" türünde bir tarama yaparak başlayın:

![](<../../.gitbook/assets/image (887).png>)

Sonra, değeri değiştirin, **değerin nasıl değiştiğini** belirtin (benim durumumda 1 azaldı) ve **bir sonraki taramayı yapın**:

![](<../../.gitbook/assets/image (368).png>)

Seçilen şekilde **değiştirilen tüm değerlerle karşılaşacaksınız**:

![](<../../.gitbook/assets/image (566).png>)

Değerinizi bulduktan sonra, onu değiştirebilirsiniz.

Unutulmaması gereken bir **çok sayıda olası değişiklik** olduğu ve sonuçları filtrelemek için bu adımları **istediğiniz kadar yapabileceğinizdir**:

![](<../../.gitbook/assets/image (571).png>)

### Rastgele Bellek Adresi - Kodu Bulma

Şimdiye kadar bir değeri saklayan bir adresi nasıl bulacağımızı öğrendik, ancak **oyunun farklı yürütme işlemlerinde bu adresin belleğin farklı yerlerinde olma olasılığı oldukça yüksektir**. Bu adresi her zaman nasıl bulacağınızı öğrenelim.

Bahsedilen hilelerden bazılarını kullanarak, mevcut oyununuzun önemli değeri nerede sakladığını bulun. Ardından (oyunu durdurarak isterseniz) bulunan **adrese sağ tıklayın** ve "**Bu adresi kimin eriştiğini bul**" veya "**Bu adrese yazanı bul**" seçeneğini belirleyin:

![](<../../.gitbook/assets/image (1064).png>)

**İlk seçenek**, bu **adresi kullanan kod parçalarını** bilmek için yararlıdır (bu, oyunun kodunu değiştirebileceğiniz yerleri bilmek gibi daha fazla şey için faydalıdır).\
**İkinci seçenek** daha **belirli** ve bu durumda **bu değerin nereden yazıldığını bilmek** için daha faydalı olacaktır.

Bu seçeneklerden birini seçtikten sonra, **hata ayıklayıcı** programı programa **bağlanacak** ve yeni bir **boş pencere** görünecektir. Şimdi, **oyunu oynayın** ve **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren adreslerle dolmalıdır**:

![](<../../.gitbook/assets/image (88).png>)

Değeri değiştiren adresi bulduğunuzda, kodu **istediğiniz gibi değiştirebilirsiniz** (Cheat Engine, bunu hızlıca NOP'larla değiştirmenize izin verir):

![](<../../.gitbook/assets/image (1054).png>)

Artık kodu, sayınızı etkilemeyecek şekilde değiştirebilir veya her zaman olumlu bir şekilde etkileyecek şekilde değiştirebilirsiniz.
### Rastgele Bellek Adresi - İşaretçiyi Bulma

Önceki adımları takip ederek ilgilendiğiniz değerin nerede olduğunu bulun. Ardından, "**Bu adrese yazan şeyleri bulun**" kullanarak bu değeri yazan adresi bulun ve üzerine çift tıklayarak açıklama görünümünü alın:

![](<../../.gitbook/assets/image (1036).png>)

Daha sonra, yeni bir tarama yaparak "\[\]" arasındaki onaltılık değeri arayın (bu durumda $edx değeri):

![](<../../.gitbook/assets/image (991).png>)

(_Birkaç tane çıkarsa genellikle en küçük adres olanı gereklidir_)\
Şimdi, ilgilendiğimiz değeri değiştirecek olan **işaretçiyi bulduk**.

"**Adresi El ile Ekle**" üzerine tıklayın:

![](<../../.gitbook/assets/image (987).png>)

Şimdi, "İşaretçi" onay kutusuna tıklayın ve bulunan adresi metin kutusuna ekleyin (bu senaryoda, önceki görüntüde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![](<../../.gitbook/assets/image (388).png>)

(İlk "Adres" kısmının işaretçi adresinden otomatik olarak dolduğuna dikkat edin)

Tamam'a tıklayın ve yeni bir işaretçi oluşturulacaktır:

![](<../../.gitbook/assets/image (305).png>)

Artık, o değeri her değiştirdiğinizde, **değeri değiştiriyorsunuz, hatta değerin bulunduğu bellek adresi farklı olsa bile.**

### Kod Enjeksiyonu

Kod enjeksiyonu, bir kod parçasını hedef sürece enjekte ettiğiniz ve ardından kodun yürütülmesini kendi yazdığınız kod üzerinden yönlendirdiğiniz bir tekniktir (örneğin, puanları azaltmak yerine puan vermek gibi).

Öyleyse, oyuncunuzun yaşamını 1 azaltan adresi bulduğunuzu hayal edin:

![](<../../.gitbook/assets/image (200).png>)

Disassembler'ı görmek için Tıklayın.\
Daha sonra, **CTRL+a**'ya basarak Otomatik montaj penceresini çağırın ve _**Şablon --> Kod Enjeksiyonu**_ seçin

![](<../../.gitbook/assets/image (899).png>)

**Değiştirmek istediğiniz talimatın adresini** doldurun (bu genellikle otomatik olarak doldurulur):

![](<../../.gitbook/assets/image (741).png>)

Bir şablon oluşturulacaktır:

![](<../../.gitbook/assets/image (941).png>)

Yeni montaj kodunuzu "**newmem**" bölümüne ekleyin ve "**originalcode**" bölümündeki orijinal kodu kaldırmak istiyorsanız kaldırın. Bu örnekte, enjekte edilen kod 1 çıkarmak yerine 2 puan ekleyecektir:

![](<../../.gitbook/assets/image (518).png>)

**Yürütülecek ve benzeri şeyler üzerine tıklayın ve kodunuz programda enjekte edilmeli ve işlevin davranışını değiştirmelidir!**

## **Referanslar**

* **Cheat Engine öğretici, Cheat Engine ile başlamanın nasıl yapılacağını öğrenmek için tamamlayın**

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın.**

</details>
