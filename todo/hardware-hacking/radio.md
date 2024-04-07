# Radyo

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger), GNU/Linux ve macOS için tasarlanmış ücretsiz bir dijital sinyal analizörüdür ve bilinmeyen radyo sinyallerinden bilgi çıkarmayı amaçlar. SoapySDR aracılığıyla çeşitli SDR cihazlarını destekler ve FSK, PSK ve ASK sinyallerinin ayarlanabilir demodülasyonunu, analog videoyu çözümlemeyi, kesikli sinyalleri analiz etmeyi ve analog ses kanallarını dinlemeyi (hepsi gerçek zamanlı) destekler.

### Temel Yapılandırma

Kurulumdan sonra yapılandırmayı düşünebileceğiniz birkaç şey vardır.\
Ayarlar bölümünde (ikinci sekme düğmesi) **SDR cihazını seçebilir** veya okumak için bir dosya seçebilir ve hangi frekansa ayarlanacağını ve Örnekleme hızını (PC'niz destekliyorsa 2.56Msps'ye kadar önerilir) seçebilirsiniz\\

![](<../../.gitbook/assets/image (242).png>)

GUI davranışında, PC'niz destekliyorsa birkaç şeyi etkinleştirmeniz önerilir:

![](<../../.gitbook/assets/image (469).png>)

{% hint style="info" %}
PC'nizin şeyleri yakalayamadığını fark ederseniz, OpenGL'yi devre dışı bırakmayı deneyin ve örnekleme hızını düşürün.
{% endhint %}

### Kullanımlar

* Sadece bir sinyalin bir süresini **yakalayıp analiz etmek** için "Yakalamak için it" düğmesini istediğiniz süre boyunca basılı tutun.

![](<../../.gitbook/assets/image (957).png>)

* SigDigger'ın **Tuner**'ı, sinyalleri **daha iyi yakalamaya yardımcı olur** (ancak onları da kötüleştirebilir). İdeal olarak, 0 ile başlayın ve ihtiyacınız olan sinyalin iyileştirmesinden daha fazla gürültü ekleyene kadar **büyütün**.

![](<../../.gitbook/assets/image (1096).png>)

### Radyo kanalıyla senkronize olma

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ile dinlemek istediğiniz kanalla senkronize olun, "Baseband ses önizlemesi" seçeneğini yapılandırın, gönderilen tüm bilgileri almak için bant genişliğini yapılandırın ve ardından Gürültünün gerçekten artmaya başladığı seviyeye kadar Tuner'ı ayarlayın:

![](<../../.gitbook/assets/image (582).png>)

## İlginç püf noktalar

* Bir cihaz bilgi patlamaları gönderdiğinde, genellikle **ilk kısım bir önsöz olacaktır**, bu yüzden **bilgi bulamazsanız** veya orada **bazı hatalar varsa endişelenmenize gerek yoktur**.
* Bilgi çerçevelerinde genellikle **iyi hizalanmış farklı çerçeveler bulmanız gerekir**:

![](<../../.gitbook/assets/image (1073).png>)

![](<../../.gitbook/assets/image (594).png>)

* **Bitleri kurtardıktan sonra onları bir şekilde işlemeniz gerekebilir**. Örneğin, Manchester kodlamasında yukarı+aşağı bir 1 veya 0 olacak ve aşağı+yukarı diğeri olacaktır. Yani 1'ler ve 0'lar (yukarı ve aşağılar) gerçek bir 1 veya gerçek bir 0 olacaktır.
* Bir sinyal Manchester kodlaması kullanıyor olsa bile (art arda iki 0 veya 1 bulmak imkansızdır), **önsözde bir arada birkaç 1 veya 0 bulabilirsiniz**!

### IQ ile modülasyon türünü açığa çıkarma

Sinyallerde bilgi depolamanın 3 yolu vardır: **Genlik**, **frekans** veya **faz**'ı modüle etmek.\
Bir sinyali kontrol ediyorsanız, bilginin nasıl depolandığını anlamaya çalışmanın farklı yolları vardır (daha fazla yol aşağıda) ancak bunlardan biri IQ grafiğini kontrol etmektir.

![](<../../.gitbook/assets/image (785).png>)

* **AM Algılama**: IQ grafiğinde örneğin **2 daire** görünüyorsa (muhtemelen biri 0'da ve diğeri farklı bir genlikte), bu bir AM sinyali olabilir. Çünkü IQ grafiğinde 0 ile daire arasındaki mesafe sinyalin genliğidir, bu nedenle farklı genliklerin kullanıldığını görselleştirmek kolaydır.
* **PM Algılama**: Önceki resimde olduğu gibi, birbirleriyle ilişkili olmayan küçük daireler bulursanız, muhtemelen bir faz modülasyonu kullanılıyor demektir. Çünkü IQ grafiğinde, nokta ile 0,0 arasındaki açı sinyalin fazıdır, bu da 4 farklı fazın kullanıldığı anlamına gelir.
* Bilgi, bir fazın değiştiği gerçeğinde gizli ise ve fazın kendisinde değilse, farklı fazları net bir şekilde ayırt edemezsiniz.
* **FM Algılama**: IQ'da frekansları tanımlamak için bir alan yoktur (merkeze olan mesafe genliktir ve açı fazdır).\
Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde bir daire görmelisiniz**.\
Ayrıca, farklı bir frekans, bu grafiğe **daire etrafında hızlanma** ile "temsil edilir" (bu nedenle SysDigger'da sinyali seçerken IQ grafiği oluşturulur, eğer oluşturulan dairede hızlanma veya yönde değişiklik bulursanız, bu FM olabilir):

## AM Örneği

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM Açığa Çıkarma

#### Zarfı kontrol etme

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ile AM bilgisini kontrol ederken ve sadece **zarfa bakarak** farklı net genlik seviyelerini görebilirsiniz. Kullanılan sinyal, AM'de bilgi gönderen darbeler gönderiyor, işte bir darbe nasıl görünüyor:

![](<../../.gitbook/assets/image (587).png>)

Ve bu, sembolün bir kısmının dalga formuyla nasıl göründüğü:

![](<../../.gitbook/assets/image (731).png>)

#### Histogramı kontrol etme

Bilginin bulunduğu yeri **tüm sinyali seçebilir**, **Genlik** modunu seçebilir ve **Seçim** ve **Histogram** üzerine tıklayabilirsiniz. Yalnızca 2 net seviye bulunduğunu görebilirsiniz

![](<../../.gitbook/assets/image (261).png>)

Örneğin, bu AM sinyalinde Genlik yerine Frekansı seçerseniz, yalnızca 1 frekans bulursunuz (frekansta modüle edilen bilgiyi kullanmanın tek yolu olan 1 frekansı kullanıyor olabilir).

![](<../../.gitbook/assets/image (729).png>)

Eğer birçok frekans bulursanız, bu muhtemelen bir FM olmayacaktır, muhtemelen sinyal frekansı sadece kanaldan dolayı değiştirilmiştir.
#### IQ ile

Bu örnekte **büyük bir daire** olduğunu görebilirsiniz ama aynı zamanda **merkezde birçok nokta** bulunmaktadır.

![](<../../.gitbook/assets/image (219).png>)

### Sembol Oranını Al

#### Bir sembolle

Bulabileceğiniz en küçük sembolü seçin (böylece sadece 1 olduğundan emin olun) ve "Seçim frekansını" kontrol edin. Bu durumda 1.013kHz olacaktır (yani 1kHz).

![](<../../.gitbook/assets/image (75).png>)

#### Bir grup sembolle

Seçeceğiniz sembol sayısını belirtebilir ve SigDigger 1 sembolün frekansını hesaplayacaktır (muhtemelen seçilen sembol sayısı ne kadar fazlaysa o kadar iyi). Bu senaryoda 10 sembol seçtim ve "Seçim frekansı" 1.004 Khz'dir:

![](<../../.gitbook/assets/image (1005).png>)

### Bitleri Al

Bu sinyalin **AM modülasyonlu** olduğunu bulduktan ve **sembol oranını** (ve bu durumda yukarı bir şeyin 1'i ve aşağı bir şeyin 0'ı temsil ettiğini bildiğinizde), sinyalde kodlanmış **bitleri elde etmek** çok kolaydır. Bu nedenle, sinyali bilgi ile seçin ve örnekleme ve karar yapılandırmasını yapılandırın ve örnekleme düğmesine basın (kontrol edin ki **Genlik** seçilmiş, keşfedilen **Sembol oranı** yapılandırılmış ve **Gadner saat kurtarma** seçilmiş):

![](<../../.gitbook/assets/image (962).png>)

* **Seçim aralıklarına senkronize et** önce sembol oranını bulmak için aralıkları seçtiyseniz, o sembol oranı kullanılacaktır.
* **Manuel** belirtilen sembol oranının kullanılacağı anlamına gelir
* **Sabit aralık seçimi** ile seçilmesi gereken aralık sayısını belirtir ve sembol oranını buna göre hesaplar
* **Gadner saat kurtarma** genellikle en iyi seçenektir, ancak yaklaşık bir sembol oranı belirtmeniz yine de gereklidir.

Örnekleme düğmesine bastığınızda şu görünür:

![](<../../.gitbook/assets/image (641).png>)

Şimdi, SigDigger'ın anlamasını sağlamak için **bilgi taşıyan seviyenin aralığının nerede olduğunu** anlamak için **düşük seviyeye** tıklayın ve en büyük seviyeye kadar tıklayarak basılı tutun:

![](<../../.gitbook/assets/image (436).png>)

Örneğin **4 farklı genlik seviyesi** olsaydı, **Sembol başına bitleri 2 olarak yapılandırmanız** ve en küçükten en büyüğe doğru seçmeniz gerekecekti.

Son olarak **Yakınlaştırma** ve **Satır boyutunu değiştirerek** bitleri görebilirsiniz (ve tümünü seçip kopyalayarak tüm bitleri alabilirsiniz):

![](<../../.gitbook/assets/image (273).png>)

Eğer sinyal sembol başına 1'den fazla bit içeriyorsa (örneğin 2), SigDigger'ın **00, 01, 10, 11** hangi sembol olduğunu bilme **yolu yoktur**, bu nedenle her birini temsil etmek için farklı **gri tonları** kullanır (ve bitleri kopyalarsanız **0'dan 3'e kadar sayılar** kullanacaktır, bunları işlemeniz gerekecektir).

Ayrıca, **Manchester** gibi **kodlamaları** kullanın ve **yukarı+aşağı** bir 1 veya 0 olabilir ve aşağı+yukarı bir 1 veya 0 olabilir. Bu durumlarda, elde edilen yukarı (1) ve aşağı (0) değerleri **01 veya 10 çiftlerini 0'lar veya 1'ler olarak değiştirmeniz gerekecektir**.

## FM Örneği

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM'nin Ortaya Çıkarılması

#### Frekansları ve dalga formunu kontrol etme

FM'de modüle edilmiş bilgi gönderen sinyal örneği:

![](<../../.gitbook/assets/image (722).png>)

Önceki görüntüde **2 frekansın kullanıldığını** oldukça iyi görebilirsiniz ama **dalga formunu gözlemlediğinizde** muhtemelen **2 farklı frekansı doğru bir şekilde tanımlayamayabilirsiniz**:

![](<../../.gitbook/assets/image (714).png>)

Bu, sinyali her iki frekansta da yakaladığım için, bu nedenle biri diğerine yaklaşık olarak negatif olacaktır:

![](<../../.gitbook/assets/image (939).png>)

Eşitlenmiş frekans **bir frekansa diğerinden daha yakınsa**, 2 farklı frekansı kolayca görebilirsiniz:

![](<../../.gitbook/assets/image (419).png>)

![](<../../.gitbook/assets/image (485).png>)

#### Histogramı kontrol etme

Bilgi içeren sinyalin frekans histogramunu kontrol ederek kolayca 2 farklı sinyali görebilirsiniz:

![](<../../.gitbook/assets/image (868).png>)

Bu durumda **Genlik histogramını** kontrol ederseniz **yalnızca bir genlik** bulacaksınız, bu yüzden **AM olamaz** (eğer birçok genlik bulursanız, sinyalin kanal boyunca güç kaybettiği anlamına gelebilir):

![](<../../.gitbook/assets/image (814).png>)

Ve bu, faz histogramı olacaktır (bu, sinyalin fazda modüle edilmediğini çok açık bir şekilde gösterir):

![](<../../.gitbook/assets/image (993).png>)

#### IQ ile

IQ'nun frekansları tanımlamak için bir alanı yoktur (merkeze olan uzaklık genlik ve açı fazdır). Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde sadece bir daire** görmelisiniz. Ayrıca, IQ grafiğinde **farklı bir frekans**, daire boyunca **hızlanma ile temsil edilir** (bu nedenle, SysDigger'da sinyali seçerken IQ grafiği oluşturulur, oluşturulan dairede bir hızlanma veya yönlendirme değişikliği bulursanız, bu FM olabilir demektir):

![](<../../.gitbook/assets/image (78).png>)

### Sembol Oranını Al

Frekansları taşıyan sembolleri bulduktan sonra sembol oranını almak için **AM örneğinde kullanılan teknikle aynı tekniği** kullanabilirsiniz.

### Bitleri Al

Sinyalin frekansla modüle edildiğini ve sembol oranını bulduktan sonra bitleri almak için **AM örneğinde kullanılan tekniği** kullanabilirsiniz.

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin**.
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>
