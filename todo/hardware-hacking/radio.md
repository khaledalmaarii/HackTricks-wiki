# Radyo

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger), GNU/Linux ve macOS için tasarlanmış ücretsiz bir dijital sinyal analizörüdür ve bilinmeyen radyo sinyallerinden bilgi çıkarmayı amaçlar. SoapySDR aracılığıyla çeşitli SDR cihazlarını destekler ve FSK, PSK ve ASK sinyallerinin ayarlanabilir demodülasyonunu, analog videoyu çözümlemeyi, kesikli sinyalleri analiz etmeyi ve analog ses kanallarını dinlemeyi (hepsi gerçek zamanlı) sağlar.

### Temel Yapılandırma

Kurduktan sonra yapılandırmayı düşünebileceğiniz birkaç şey var.\
Ayarlar bölümünde (ikinci sekme düğmesi) **SDR cihazını seçebilir** veya okumak için bir **dosya seçebilir** ve hangi frekansı senkronize etmek istediğinizi ve Örnekleme hızını (PC'niz destekliyorsa 2.56Msps'ye kadar önerilir) seçebilirsiniz\\

![](<../../.gitbook/assets/image (245).png>)

GUI davranışında, PC'niz destekliyorsa birkaç şeyi etkinleştirmeniz önerilir:

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
PC'nizin şeyleri yakalayamadığını fark ederseniz, OpenGL'yi devre dışı bırakmayı deneyin ve örnekleme hızını düşürün.
{% endhint %}

### Kullanımlar

* Sadece bir sinyalin bir süresini **yakalayıp analiz etmek** için "Yakalamak için it" düğmesini istediğiniz süre boyunca basılı tutun.

![](<../../.gitbook/assets/image (960).png>)

* SigDigger'ın **Tuner**'ı, sinyalleri **daha iyi yakalamaya yardımcı olur** (ancak onları da kötüleştirebilir). İdeal olarak, gürültüyü bulana kadar 0 ile başlayın ve ihtiyacınız olan sinyalin iyileştirmesinden daha büyük olduğunu görene kadar **büyütmeye devam edin**).

![](<../../.gitbook/assets/image (1099).png>)

### Radyo kanalıyla senkronize etme

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ile dinlemek istediğiniz kanalla senkronize olun, "Baseband ses önizlemesi" seçeneğini yapılandırın, gönderilen tüm bilgileri almak için bant genişliğini yapılandırın ve ardından Gürültünün gerçekten artmaya başladığı seviyeye kadar Tuner'ı ayarlayın:

![](<../../.gitbook/assets/image (585).png>)

## İlginç püf noktalar

* Bir cihaz bilgi patlamaları gönderdiğinde, genellikle **ilk kısım bir önsöz olacaktır**, bu yüzden **bilgi bulamazsanız endişelenmenize gerek yok** ya da orada **bazı hatalar varsa**.
* Bilgi çerçevelerinde genellikle **iyi hizalanmış farklı çerçeveler bulmanız gerekir**:

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **Bitleri kurtardıktan sonra onları bir şekilde işlemeniz gerekebilir**. Örneğin, Manchester kodlamasında yukarı+aşağı bir 1 veya 0 olacak ve aşağı+yukarı diğeri olacaktır. Yani 1'ler ve 0'lar (yukarılar ve aşağılar) gerçek bir 1 veya gerçek bir 0 olacaktır.
* Bir sinyal Manchester kodlaması kullanıyor olsa bile (ardışık olarak iki 0 veya 1 bulmak imkansızdır), **önsözde bir araya gelen birkaç 1 veya 0 bulabilirsiniz**!

### IQ ile modülasyon türünü açığa çıkarma

Sinyallerde bilgi depolamanın 3 yolu vardır: **Genliği**, **frekansı** veya **fazı** modüle etmek.\
Bir sinyali kontrol ediyorsanız, bilginin nasıl depolandığını anlamaya çalışmanın farklı yolları vardır (daha fazla yol aşağıda) ancak bunlardan biri IQ grafiğini kontrol etmektir.

![](<../../.gitbook/assets/image (788).png>)

* **AM Algılama**: IQ grafiğinde örneğin **2 daire** görünüyorsa (muhtemelen biri 0'da ve diğeri farklı bir genlikte), bu bir AM sinyali olabilir. Çünkü IQ grafiğinde 0 ile daire arasındaki mesafe sinyalin genliğidir, bu nedenle farklı genliklerin kullanıldığını görselleştirmek kolaydır.
* **PM Algılama**: Önceki resimde olduğu gibi, birbirleriyle ilişkili olmayan küçük daireler bulursanız, muhtemelen bir faz modülasyonu kullanılıyor demektir. Çünkü IQ grafiğinde, nokta ile 0,0 arasındaki açı sinyalin fazıdır, bu da 4 farklı fazın kullanıldığı anlamına gelir.
* Bilgi, bir fazın değiştirildiği gerçeğinde gizli ise ve fazın kendisinde değilse, farklı fazları net bir şekilde ayırt edemezsiniz.
* **FM Algılama**: IQ'da frekansları tanımlamak için bir alan yoktur (merkeze olan mesafe genlik ve açı fazdır).\
Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde bir daire görmelisiniz**.\
Ayrıca, farklı bir frekans, IQ grafiğinde bir **hız ivmesiyle temsil edilir** (bu nedenle SysDigger'da sinyali seçerken IQ grafiği oluşturulur, eğer oluşturulan dairede bir ivme veya yönde değişiklik bulursanız, bu FM olabilir):

## AM Örneği

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM Açığa Çıkarma

#### Zarfı kontrol etme

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ile AM bilgilerini kontrol ederken ve sadece **zarfa bakarak** farklı net genlik seviyeleri görebilirsiniz. Kullanılan sinyal, AM'de bilgi gönderen darbeler gönderiyor, işte bir darbe nasıl görünüyor:

![](<../../.gitbook/assets/image (590).png>)

Ve bu, sembolün bir kısmının dalga formuyla nasıl göründüğü:

![](<../../.gitbook/assets/image (734).png>)

#### Histogramı kontrol etme

Bilginin bulunduğu yeri **tüm sinyali seçebilir**, **Genlik** modunu seçebilir ve **Seçim** ve **Histogram** üzerine tıklayabilirsiniz. 2 net seviyenin bulunduğunu gözlemleyebilirsiniz

![](<../../.gitbook/assets/image (264).png>)

Örneğin, bu AM sinyalinde Genlik yerine Frekansı seçerseniz, sadece 1 frekans bulursunuz (bilginin frekansta modüle edilmesi mümkün değilse sadece 1 frekans kullanılıyor demektir).

![](<../../.gitbook/assets/image (732).png>)

Eğer birçok frekans bulursanız, bu muhtemelen bir FM olmayacaktır, muhtemelen sinyal frekansı sadece kanaldan dolayı değiştirilmiştir.
#### IQ ile

Bu örnekte **büyük bir daire** olduğunu görebilirsiniz ama aynı zamanda **merkezde birçok nokta da var.**

![](<../../.gitbook/assets/image (222).png>)

### Sembol Oranını Al

#### Bir sembolle

Bulabileceğiniz en küçük sembolü seçin (böylece sadece 1 olduğundan emin olun) ve "Seçim frekansını" kontrol edin. Bu durumda 1.013kHz olacaktır (yani 1kHz).

![](<../../.gitbook/assets/image (78).png>)

#### Bir grup sembolle

Seçeceğiniz sembol sayısını belirtebilir ve SigDigger 1 sembolün frekansını hesaplayacaktır (muhtemelen seçilen sembol sayısı ne kadar fazlaysa o kadar iyi). Bu senaryoda 10 sembol seçtim ve "Seçim frekansı" 1.004 Khz'dir:

![](<../../.gitbook/assets/image (1008).png>)

### Bitleri Al

Bu sinyalin **AM modüle** olduğunu ve **sembol oranını** bulduktan sonra (ve bu durumda yukarı bir şeyin 1'i ve aşağı bir şeyin 0'ı temsil ettiğini bildiğinizde), sinyalde kodlanmış **bitleri elde etmek** çok kolaydır. Bu nedenle, sinyali bilgi ile seçin ve örnekleme ve karar yapılandırmasını yapın ve örnekleme düğmesine basın (kontrol edin ki **Genlik** seçilmiş, keşfedilen **Sembol oranı** yapılandırılmış ve **Gardner saat kurtarma** seçilmiş):

![](<../../.gitbook/assets/image (965).png>)

* **Seçim aralıklarına senkronize et** önce sembol oranını bulmak için aralıkları seçtiyseniz, o sembol oranı kullanılacaktır.
* **Manuel** belirtilen sembol oranının kullanılacağı anlamına gelir
* **Sabit aralık seçimi** ile seçilmesi gereken aralık sayısını belirtir ve sembol oranını buna göre hesaplar
* **Gardner saat kurtarma** genellikle en iyi seçenektir, ancak yine de yaklaşık bir sembol oranı belirtmeniz gerekir.

Örnekleme düğmesine bastığınızda şu görünür:

![](<../../.gitbook/assets/image (644).png>)

Şimdi, SigDigger'ın **bilgi taşıyan seviyenin aralığını nerede anlamasını** sağlamak için **bilgi taşıyan seviyenin en altına** tıklayın ve en büyük seviyeye kadar tıklamaya devam edin:

![](<../../.gitbook/assets/image (439).png>)

Örneğin **4 farklı genlik seviyesi** olsaydı, **Sembol başına bitleri 2 olarak yapılandırmanız** ve en küçükten en büyüğe doğru seçmeniz gerekirdi.

Son olarak **Yakınlaştırma** ve **Satır boyutunu değiştirerek** bitleri görebilirsiniz (ve tümünü seçip kopyalayarak tüm bitleri alabilirsiniz):

![](<../../.gitbook/assets/image (276).png>)

Eğer sinyal sembol başına 1 bitden fazlaysa (örneğin 2), SigDigger'ın hangi sembolün 00, 01, 10, 11 olduğunu **bilme yolu yoktur**, bu nedenle her birini temsil etmek için farklı **gri tonları** kullanır (ve bitleri kopyalarsanız **0'dan 3'e kadar sayılar** kullanır, bunları işlemeniz gerekir).

Ayrıca, **Manchester** gibi **kodlamaları** kullanın ve **yukarı+aşağı** 1 veya 0 olabilir ve aşağı+yukarı 1 veya 0 olabilir. Bu durumlarda, elde edilen yukarıları (1) ve aşağıları (0) **işlemeniz** ve 01 veya 10 çiftlerini 0'lar veya 1'ler olarak **değiştirmeniz gerekir**.

## FM Örneği

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM'nin Ortaya Çıkarılması

#### Frekansları ve dalga formunu kontrol etme

Bilgi modüle edilmiş bir sinyal örneği gönderen FM'de:

![](<../../.gitbook/assets/image (725).png>)

Önceki görüntüde **2 frekansın kullanıldığını** oldukça iyi görebilirsiniz ama **dalga formunu gözlemlediğinizde** muhtemelen **2 farklı frekansı doğru bir şekilde tanımlayamayabilirsiniz**:

![](<../../.gitbook/assets/image (717).png>)

Bu, sinyali her iki frekansta da yakaladığım için, biri diğerine yaklaşık olarak negatif olacaktır:

![](<../../.gitbook/assets/image (942).png>)

Senkronize frekans **bir frekansa diğerinden daha yakınsa**, 2 farklı frekansı kolayca görebilirsiniz:

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### Histogramı kontrol etme

Bilgi içeren sinyalin frekans histogramunu kontrol ederek kolayca 2 farklı sinyali görebilirsiniz:

![](<../../.gitbook/assets/image (871).png>)

Bu durumda **Genlik histogramını** kontrol ederseniz **yalnızca bir genlik** bulacaksınız, bu yüzden **AM olamaz** (eğer birçok genlik bulursanız, sinyalin kanal boyunca güç kaybettiği anlamına gelebilir):

![](<../../.gitbook/assets/image (817).png>)

Ve bu da faz histogramı olacaktır (bu, sinyalin fazda modüle edilmediğini çok açık bir şekilde gösterir):

![](<../../.gitbook/assets/image (996).png>)

#### IQ ile

IQ'nun frekansları tanımlamak için bir alanı yoktur (merkeze olan uzaklık genlik ve açı fazdır). Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde sadece bir daire görmelisiniz**.

Ayrıca, IQ grafiğinde **farklı bir frekans**, oluşturulan dairede **bir hız ivmesi ile temsil edilir** (bu nedenle, SysDigger'da sinyali seçerken IQ grafiği oluşturulur, eğer oluşturulan dairede bir hızlanma veya yönde değişiklik bulursanız, bu FM olabilir):

![](<../../.gitbook/assets/image (81).png>)

### Sembol Oranını Al

Frekansları taşıyan sembolleri bulduktan sonra sembol oranını almak için **AM örneğinde kullanılan teknikle aynı tekniği** kullanabilirsiniz.

### Bitleri Al

Sinyalin frekansla modüle edildiğini ve sembol oranını bulduktan sonra bitleri almak için **AM örneğinde kullanılan tekniği** kullanabilirsiniz.

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 **Discord grubuna** katılın](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.** takip edin
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>
