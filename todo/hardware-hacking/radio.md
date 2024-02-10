# Radyo

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger), bilinmeyen radyo sinyallerinin bilgilerini çıkarmak için tasarlanmış ücretsiz bir dijital sinyal analizörüdür ve GNU/Linux ve macOS için kullanılabilir. SoapySDR aracılığıyla çeşitli SDR cihazlarını destekler ve FSK, PSK ve ASK sinyallerinin ayarlanabilir demodülasyonunu, analog videoyu çözümlemeyi, patlayıcı sinyalleri analiz etmeyi ve analog ses kanallarını dinlemeyi (hepsi gerçek zamanlı olarak) sağlar.

### Temel Yapılandırma

Kurulumdan sonra yapılandırmanızı düşünebileceğiniz birkaç şey vardır.\
Ayarlar (ikinci sekme düğmesi) bölümünde **SDR cihazını seçebilir** veya **okumak için bir dosya seçebilirsiniz** ve hangi frekansa ayarlanacağını ve Örnekleme hızını (PC'niz bunu destekliyorsa 2.56Msps'ye kadar önerilir) seçebilirsiniz.\\

![](<../../.gitbook/assets/image (655) (1).png>)

GUI davranışında, PC'niz bunu destekliyorsa birkaç şeyi etkinleştirmeniz önerilir:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
PC'nizin şeyleri yakalamadığını fark ederseniz, OpenGL'yi devre dışı bırakmayı ve örnekleme hızını düşürmeyi deneyin.
{% endhint %}

### Kullanımlar

* Sadece bir sinyalin **bir süresini yakalamak ve analiz etmek** için "Yakalamak için basın" düğmesini istediğiniz süre boyunca basılı tutun.

![](<../../.gitbook/assets/image (631).png>)

* SigDigger'ın **Tuner**'ı, sinyalleri daha iyi yakalamaya yardımcı olur (ancak aynı zamanda onları bozabilir). İdeal olarak, 0 ile başlayın ve ihtiyacınız olan sinyalin iyileştirmesinden daha büyük olan gürültüyü bulana kadar **daha büyük hale getirin**.

![](<../../.gitbook/assets/image (658).png>)

### Radyo kanalıyla senkronize etme

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ile duymak istediğiniz kanalla senkronize olmak için "Baseband ses önizlemesi" seçeneğini yapılandırın, gönderilen tüm bilgileri almak için bant genişliğini yapılandırın ve ardından Gürültü gerçekten artmaya başlamadan önce Tuner'ı ayarlayın:

![](<../../.gitbook/assets/image (389).png>)

## İlginç hileler

* Bir cihaz bilgi patlamaları gönderdiğinde, genellikle **ilk kısım bir önsöz olacak**, bu yüzden orada bilgi bulamazsanız veya hatalar varsa endişelenmenize gerek yok.
* Bilgi çerçevelerinde genellikle **birbirleriyle iyi hizalanmış farklı çerçeveler bulmanız gerekir**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Bitleri kurtardıktan sonra onları bir şekilde işlemeniz gerekebilir**. Örneğin, Manchester kodlamada yukarı+aşağı bir 1 veya 0 olacak ve aşağı+yukarı diğeri olacak. Yani, 1'ler ve 0'lar (yukarılar ve aşağılar) çiftleri gerçek bir 1 veya gerçek bir 0 olacaktır.
* Bir sinyal Manchester kodlaması kullanıyor olsa bile (ardışık olarak iki tane 0 veya 1 bulmak imkansızdır), önsözde **bir araya gelen birkaç 1 veya 0 bulabilirsiniz**!

### IQ ile modülasyon türünü ortaya çıkarma

Sinyallerde bilgiyi depolamanın 3 yolu vardır: **Amplitüdü**, **frekansı** veya **fazı** modüle etmek.\
Bir sinyali kontrol ediyorsanız, bilgiyi depolamak için neyin kullanıldığını anlamaya çalışmanın farklı yolları vardır (daha fazla yol aşağıda), ancak iyi bir yol IQ grafiğini kontrol etmektir.

![](<../../.gitbook/assets/image (630).png>)

* **AM Algılama**: IQ grafiğinde örneğin **2 daire** görünüyorsa (muhtemelen biri 0'da ve diğeri farklı bir amplitüde), bu bir AM sinyali olabilir. Bu, IQ grafiğinde 0 ile daire arasındaki mesafenin sinyalin amplitüdü olduğu için farklı amplitüdlerin kullanıldığını görselleştirmek kolaydır.
* **PM Algılama**: Önceki resimde olduğu gibi, birbirleriyle ilgisi olmayan küçük daireler bulursanız, muhtemelen bir faz modülasyonu kullanılıyor demektir. Bu, IQ grafiğinde nokta ile 0,0 arasındaki açının sinyalin fazı olduğu anlamına gelir, bu da 4 farklı fazın kullanıldığı anlamına gelir.
* Bilgi, bir fazın kendisi değil, bir fazın değiştiği gerçeğine gizlenmişse, farklı fazları net bir şekilde ayırt edemezsiniz.
* **FM Algılama**: IQ'da frekansları tanımlamak için bir alan yoktur (merkeze olan mesafe amplitüd ve açı fazdır).\
Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde sadece bir daire** görmelisiniz.\
Ayrıca, farklı bir frekans, oluşturulan dairede bir **hız ivmesi ile "temsil" edilir** (bu nedenle SysDigger'da sinyali seçerken IQ grafiği oluşturulur, oluşturulan dairede bir ivme veya yönelim değişikliği bulursanız, bu FM olabilir):

## AM Örneği

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM'i Ortaya Çıkarma

#### Zarfı kontrol etme

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ile AM bilgisini kontrol etmek ve sadece **zarfa** bakarak farklı net amplitüd seviyeleri görebilir
#### IQ ile

Bu örnekte, **büyük bir daire** olduğunu ve aynı zamanda **merkezde birçok nokta** olduğunu görebilirsiniz.

![](<../../.gitbook/assets/image (640).png>)

### Sembol Oranını Al

#### Bir sembolle

Bulabileceğiniz en küçük sembolü seçin (böylece sadece 1 olduğundan emin olun) ve "Seçim frekansını" kontrol edin. Bu durumda 1.013 kHz (yani 1 kHz) olacaktır.

![](<../../.gitbook/assets/image (638) (1).png>)

#### Bir sembol grubuyla

Ayrıca seçeceğiniz sembol sayısını belirtebilir ve SigDigger, 1 sembolün frekansını hesaplar (seçilen sembol sayısı ne kadar fazla olursa o kadar iyi olur). Bu senaryoda 10 sembol seçtim ve "Seçim frekansı" 1.004 Khz'dir:

![](<../../.gitbook/assets/image (635).png>)

### Bitleri Al

Bu sinyalin **AM modülasyonlu** olduğunu ve **sembol oranını** bulduktan sonra (ve bu durumda yukarı bir şeyin 1 ve aşağı bir şeyin 0 anlamına geldiğini bilerek), sinyalde kodlanmış olan bitleri elde etmek çok kolaydır. Bu nedenle, sinyali bilgiyle seçin ve örnekleme ve karar verme işlemini yapılandırın ve örnekleme düğmesine basın (kontrol edin ki **Amplitude** seçili, keşfedilen **Sembol oranı** yapılandırılmış ve **Gadner saat geri kazanımı** seçili):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Seçim aralıklarına senkronize et** önceden sembol oranını bulmak için aralıkları seçtiyseniz, o sembol oranı kullanılacaktır.
* **Manuel** sembol oranının kullanılacağı anlamına gelir
* **Sabit aralık seçimi**'nde seçilecek aralık sayısını belirtir ve sembol oranını ondan hesaplar
* **Gadner saat geri kazanımı** genellikle en iyi seçenektir, ancak yaklaşık sembol oranını belirtmeniz gerekmektedir.

Örnekleme düğmesine bastığınızda aşağıdaki gibi bir görüntü belirir:

![](<../../.gitbook/assets/image (659).png>)

Şimdi, SigDigger'ın bilginin taşındığı seviye aralığını anlamasını sağlamak için **daha düşük seviyeye** tıklayın ve en büyük seviyeye kadar tıklamaya devam edin:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

Örneğin **4 farklı amplitüd seviyesi** olsaydı, **Sembol başına bit**'i 2 olarak yapılandırmanız ve en küçükten en büyüğe doğru seçmeniz gerekecekti.

Son olarak, **Yakınlaştırma**'yı **artırarak** ve **Satır boyutunu değiştirerek** bitleri görebilirsiniz (ve tümünü seçip kopyalayarak tüm bitleri alabilirsiniz):

![](<../../.gitbook/assets/image (649) (1).png>)

Eğer sinyal sembol başına 1'den fazla bit içeriyorsa (örneğin 2), SigDigger'ın hangi sembolün 00, 01, 10, 11 olduğunu bilmesi **mümkün değildir**, bu nedenle her birini temsil etmek için farklı **gri tonları** kullanır (ve bitleri kopyalarsanız 0'dan 3'e kadar **sayılar kullanır**, bunları işlemeniz gerekecektir).

Ayrıca, **Manchester** gibi **kodlamaları** kullanabilirsiniz ve **yukarı+aşağı** 1 veya 0 olabilir ve aşağı+yukarı 1 veya 0 olabilir. Bu durumlarda, elde edilen yukarıları (1) ve aşağıları (0) 01 veya 10 çiftlerini 0 veya 1 olarak değiştirmeniz gerekmektedir.

## FM Örneği

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM'nin Ortaya Çıkarılması

#### Frekansları ve dalga formunu kontrol etme

Bilgi modülasyonlu sinyal örneği gönderen sinyal:

![](<../../.gitbook/assets/image (661) (1).png>)

Önceki görüntüde **2 farklı frekansın kullanıldığını** görebilirsiniz, ancak **dalga formunu** gözlemlediğinizde **2 farklı frekansı doğru bir şekilde tanımlayamayabilirsiniz**:

![](<../../.gitbook/assets/image (653).png>)

Bu, sinyali her iki frekansta da yakaladığım için biri diğerine yaklaşık olarak negatif olan durumdur:

![](<../../.gitbook/assets/image (656).png>)

Senkronize frekans, **diğer frekansa göre daha yakınsa**, 2 farklı frekansı kolayca görebilirsiniz:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Histogramı kontrol etme

Bilgi içeren sinyalin frekans histogramını kontrol ettiğinizde kolayca 2 farklı sinyal görebilirsiniz:

![](<../../.gitbook/assets/image (657).png>)

Bu durumda **Amplitüd histogramını** kontrol ederseniz, **yalnızca bir amplitüd** bulursunuz, bu yüzden **AM olamaz** (eğer birçok amplitüd bulursanız, sinyalin kanal boyunca güç kaybettiği anlamına gelebilir):

![](<../../.gitbook/assets/image (646).png>)

Ve bu, faz histogramı olacaktır (bu, sinyalin fazda modüle edilmediğini çok net bir şekilde gösterir):

![](<../../.gitbook/assets/image (201) (2).png>)

#### IQ ile

IQ'nun frekansları tanımlamak için bir alanı yoktur (merkeze olan mesafe amplitüd ve açı fazdır). Bu nedenle, FM'yi tanımlamak için bu grafikte **temel olarak sadece bir daire** görmelisiniz. Ayrıca, farklı bir frekans, IQ grafiğinde bir **hız ivmesiyle temsil edilir** (bu nedenle SysDigger'da sinyali seçtiğinizde IQ grafiği oluşturulurken bir ivme veya yönlendirme değişikliği bulursanız, bu FM olabilir):

![](<../../.gitbook/assets/image (643) (1).png>)

### Sembol Oranını Al

Frekans taşıyan semboller bulduktan sonra, sembol oranını elde etmek için **AM örneğinde kullanılan aynı teknik**i kullanabilirsiniz.

### Bitleri Al

Sinyalin frekans modülasyonlu olduğunu ve sembol oranını bulduktan sonra, bitleri elde etmek için **AM örneğinde kullanılan aynı teknik**i kullanabilirsiniz.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlosp
