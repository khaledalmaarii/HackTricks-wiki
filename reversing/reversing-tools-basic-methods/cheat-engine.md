# Hile Motoru

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

[**Hile Motoru**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmanıza ve değiştirmenize olanak tanıyan faydalı bir programdır.\
İndirip çalıştırdığınızda, aracı nasıl kullanacağınıza dair bir eğitimle karşılaşırsınız. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız, eğitimi tamamlamanız şiddetle tavsiye edilir.

## Ne arıyorsunuz?

![](<../../.gitbook/assets/image (762).png>)

Bu araç, bir programın belleğinde **bazı değerlerin** (genellikle bir sayı) **nerede saklandığını** bulmak için çok faydalıdır.\
**Genellikle sayılar**, **4 bayt** formunda saklanır, ancak bunları **double** veya **float** formatlarında da bulabilir veya bir sayıdan **farklı bir şey aramak isteyebilirsiniz**. Bu nedenle, aramak istediğiniz şeyi **seçtiğinizden emin olmanız gerekir**:

![](<../../.gitbook/assets/image (324).png>)

Ayrıca **farklı türlerde aramaları** belirtebilirsiniz:

![](<../../.gitbook/assets/image (311).png>)

Ayrıca, **belleği tararken oyunu durdurmak için** kutuyu işaretleyebilirsiniz:

![](<../../.gitbook/assets/image (1052).png>)

### Kısayol Tuşları

_**Düzenle --> Ayarlar --> Kısayol Tuşları**_ bölümünde, **oyunu durdurmak** gibi farklı amaçlar için farklı **kısayol tuşları** ayarlayabilirsiniz (bunu yapmak, belleği taramak istediğiniz bir noktada oldukça faydalıdır). Diğer seçenekler de mevcuttur:

![](<../../.gitbook/assets/image (864).png>)

## Değeri Değiştirme

Bir kez **aramakta olduğunuz değeri** nerede bulduysanız (bu konuyla ilgili daha fazlası aşağıdaki adımlarda), değeri çift tıklayarak değiştirebilir, ardından değerine çift tıklayarak değiştirebilirsiniz:

![](<../../.gitbook/assets/image (563).png>)

Ve son olarak, değişikliğin bellekte yapılması için işareti işaretleyin:

![](<../../.gitbook/assets/image (385).png>)

**Bellekteki değişiklik** hemen **uygulanacaktır** (oyun bu değeri tekrar kullanana kadar değer **oyunda güncellenmeyecektir**).

## Değeri Arama

Öyleyse, kullanıcınızın hayatı gibi önemli bir değeri iyileştirmek istediğinizi ve bu değeri bellekte aradığınızı varsayalım)

### Bilinen bir değişiklik aracılığıyla

Değerin 100 olduğunu arıyorsanız, bu değeri aramak için bir tarama yaparsınız ve birçok eşleşme bulursunuz:

![](<../../.gitbook/assets/image (108).png>)

Sonra, **değerin değiştiği bir şey yaparsınız**, oyunu **durdurursunuz** ve **bir sonraki taramayı** yaparsınız:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine, **100'den yeni değere geçen değerleri** arayacaktır. Tebrikler, aradığınız değerin adresini buldunuz, şimdi onu değiştirebilirsiniz.\
_Eğer hala birkaç değerin varsa, o değeri tekrar değiştirmek için bir şey yapın ve adresleri filtrelemek için başka bir "sonraki tarama" yapın._

### Bilinmeyen Değer, bilinen değişiklik

Değeri **bilmiyorsanız** ancak **nasıl değişeceğini** biliyorsanız (ve hatta değişikliğin değerini biliyorsanız), sayınızı arayabilirsiniz.

Bu nedenle, "**Bilinmeyen başlangıç değeri**" türünde bir tarama yaparak başlayın:

![](<../../.gitbook/assets/image (890).png>)

Sonra, değeri değiştirin, **değerin nasıl değiştiğini** belirtin (benim durumumda 1 azaldı) ve **bir sonraki taramayı** yapın:

![](<../../.gitbook/assets/image (371).png>)

Seçilen şekilde değiştirilen **tüm değerlerle karşılaşacaksınız**:

![](<../../.gitbook/assets/image (569).png>)

Değerinizi bulduktan sonra onu değiştirebilirsiniz.

Unutulmamalıdır ki **çok sayıda olası değişiklik** vardır ve sonuçları filtrelemek için bu adımları **istediğiniz kadar yapabilirsiniz**:

![](<../../.gitbook/assets/image (574).png>)

### Rastgele Bellek Adresi - Kodu Bulma

Bir değeri depolayan bir adresi bulmayı öğrendik, ancak **oyunun farklı yürütümlerinde bu adresin belleğin farklı yerlerinde olma olasılığı oldukça yüksektir**. Bu adresi her zaman bulmanın yolunu öğrenelim.

Bahsedilen hilelerden bazılarını kullanarak, mevcut oyununuzun önemli değeri depoladığı adresi bulun. Ardından (oyunu durdurarak isterseniz) bulunan **adrese sağ tıklayın** ve "**Bu adresi kimin eriştiğini bul**" veya "**Bu adrese yazanı bul**" seçeneğini seçin":

![](<../../.gitbook/assets/image (1067).png>)

**İlk seçenek**, bu **adresi kullanan kod parçalarını** bilmek için yararlıdır (bu, **oyunun kodunu nasıl değiştirebileceğinizi** bilmek gibi daha fazla şey için faydalıdır).\
**İkinci seçenek** daha **belirgin** ve bu durumda daha **yardımcı olacaktır** çünkü **bu değerin nereden yazıldığını** bilmek istiyoruz.

Bu seçeneklerden birini seçtikten sonra, **hata ayıklayıcı** programı programa **bağlanacak** ve yeni bir **boş pencere** görünecektir. Şimdi, **oyunu oynayın** ve **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren adreslerle dolmalıdır**:

![](<../../.gitbook/assets/image (91).png>)

Değeri değiştiren adresi bulduğunuzda, kodu **istediğiniz gibi değiştirebilirsiniz** (Cheat Engine, bunu hızlıca NOP'larla değiştirmenize izin verir):

![](<../../.gitbook/assets/image (1057).png>)

Artık kodu, sayınızı etkilemeyecek şekilde değiştirebilir veya her zaman olumlu bir şekilde etkileyecek şekilde değiştirebilirsiniz.
### Rastgele Bellek Adresi - İşaretçiyi Bulma

Önceki adımları takip ederek, ilgilendiğiniz değerin nerede olduğunu bulun. Ardından, "**Bu adrese yazan şeyleri bulun**" kullanarak bu değeri yazan adresi bulun ve üzerine çift tıklayarak açıklama görünümünü alın:

![](<../../.gitbook/assets/image (1039).png>)

Daha sonra, yeni bir tarama yapın, "\[\]" arasındaki onaltılık değeri arayın (bu durumda $edx değeri):

![](<../../.gitbook/assets/image (994).png>)

(Çoğu zaman en küçük adres olanı gerekecektir)\
Şimdi, ilgilendiğimiz değeri değiştirecek olan işaretçiyi bulduk.

"**Adresi El ile Ekle**" üzerine tıklayın:

![](<../../.gitbook/assets/image (990).png>)

Şimdi, "İşaretçi" onay kutusuna tıklayın ve bulunan adresi metin kutusuna ekleyin (bu senaryoda, önceki görüntüde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![](<../../.gitbook/assets/image (392).png>)

(İlk "Adres" kutusunun, tanıttığınız işaretçi adresinden otomatik olarak dolduğuna dikkat edin)

Tamam'a tıklayın ve yeni bir işaretçi oluşturulacaktır:

![](<../../.gitbook/assets/image (308).png>)

Artık, o değeri her değiştirdiğinizde, bellek adresinin farklı olduğu önemli değeri değiştiriyorsunuz.

### Kod Enjeksiyonu

Kod enjeksiyonu, bir parça kodu hedef sürece enjekte ettiğiniz ve ardından kodun yürütülmesini kendi yazdığınız kod üzerinden yönlendirdiğiniz bir tekniktir (örneğin, puanları dinlenmek yerine size verir).

Örneğin, oyuncunuzun yaşamını 1 azaltan adresi bulduğunuzu varsayalım:

![](<../../.gitbook/assets/image (203).png>)

Disassembler'ı görmek için Tıklayın.\
Daha sonra, Auto assemble penceresini çağırmak için **CTRL+a** tuşlarına basın ve _**Template --> Kod Enjeksiyonu**_ seçeneğini seçin

![](<../../.gitbook/assets/image (902).png>)

Değiştirmek istediğiniz talimatın adresini doldurun (bu genellikle otomatik olarak doldurulur):

![](<../../.gitbook/assets/image (744).png>)

Bir şablon oluşturulacaktır:

![](<../../.gitbook/assets/image (944).png>)

Yeni montaj kodunuzu "**newmem**" bölümüne ekleyin ve orijinal kodu "**originalcode**" bölümünden kaldırın, eğer yürütülmesini istemiyorsanız. Bu örnekte, enjekte edilen kod, 1 çıkarmak yerine 2 puan ekleyecektir:

![](<../../.gitbook/assets/image (521).png>)

**Yürüt düğmesine tıklayın ve devam edin, kodunuz programda enjekte edilerek işlevin davranışını değiştirmelidir!**

## **Referanslar**

* **Cheat Engine öğretici, Cheat Engine ile başlamanın nasıl yapılacağını öğrenmek için tamamlayın**
