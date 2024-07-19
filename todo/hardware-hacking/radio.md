# Radyo

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek hacking ipuçlarını paylaşın.

</details>
{% endhint %}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger), bilinmeyen radyo sinyallerinin bilgilerini çıkarmak için tasarlanmış, GNU/Linux ve macOS için ücretsiz bir dijital sinyal analizörüdür. SoapySDR aracılığıyla çeşitli SDR cihazlarını destekler ve FSK, PSK ve ASK sinyallerinin ayarlanabilir demodülasyonunu, analog video çözümlemesini, patlayıcı sinyalleri analiz etmeyi ve analog ses kanallarını dinlemeyi (hepsi gerçek zamanlı) sağlar.

### Temel Konfigürasyon

Kurulumdan sonra yapılandırmayı düşünebileceğiniz birkaç şey vardır.\
Ayarlar (ikinci sekme düğmesi) kısmında **SDR cihazını** seçebilir veya **bir dosya** seçerek okumak için hangi frekansa ayarlanacağını ve örnekleme hızını (PC'niz destekliyorsa 2.56Msps'a kadar önerilir) ayarlayabilirsiniz.\\

![](<../../.gitbook/assets/image (245).png>)

GUI davranışında, PC'niz destekliyorsa birkaç şeyi etkinleştirmeniz önerilir:

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
Eğer PC'nizin bir şeyleri yakalamadığını fark ederseniz, OpenGL'i devre dışı bırakmayı ve örnekleme hızını düşürmeyi deneyin.
{% endhint %}

### Kullanımlar

* Sadece **bir sinyalin bir kısmını yakalamak ve analiz etmek** için "Yakalamak için bas" butonunu ihtiyacınız olduğu sürece basılı tutun.

![](<../../.gitbook/assets/image (960).png>)

* SigDigger'ın **Tuner**'ı **daha iyi sinyaller yakalamaya** yardımcı olur (ama aynı zamanda onları bozabilir). İdeal olarak 0 ile başlayın ve **sinyalin iyileşmesinden daha büyük** olan **gürültüyü** bulana kadar **büyütmeye devam edin**.

![](<../../.gitbook/assets/image (1099).png>)

### Radyo kanalı ile senkronize olma

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ile duymak istediğiniz kanal ile senkronize olun, "Temel bant ses önizleme" seçeneğini yapılandırın, gönderilen tüm bilgileri almak için bant genişliğini ayarlayın ve ardından Tuner'ı gürültünün gerçekten artmaya başlamadan önceki seviyeye ayarlayın:

![](<../../.gitbook/assets/image (585).png>)

## İlginç ipuçları

* Bir cihaz bilgi patlamaları gönderdiğinde, genellikle **ilk kısım bir önsöz olacaktır**, bu yüzden orada **bilgi bulamazsanız** veya **bazı hatalar varsa** **endişelenmeyin**.
* Bilgi çerçevelerinde genellikle **birbirleriyle iyi hizalanmış farklı çerçeveler bulmalısınız**:

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **Bitleri geri aldıktan sonra, onları bir şekilde işlemeniz gerekebilir**. Örneğin, Manchester kodlamasında bir yukarı+aşağı 1 veya 0 olacak ve bir aşağı+yukarı diğerini temsil edecektir. Yani 1'lerin ve 0'ların çiftleri (yukarı ve aşağı) gerçek bir 1 veya gerçek bir 0 olacaktır.
* Bir sinyal Manchester kodlaması kullanıyorsa (bir sırada iki 0 veya 1'den fazlasını bulmak imkansızdır), **önsözde birden fazla 1 veya 0 bulabilirsiniz**!

### IQ ile modülasyon türünü açığa çıkarma

Sinyallerde bilgiyi depolamanın 3 yolu vardır: **amplitüd**, **frekans** veya **faz** modüle etmek.\
Bir sinyali kontrol ediyorsanız, bilgiyi depolamak için neyin kullanıldığını anlamanın farklı yolları vardır (aşağıda daha fazla yol bulabilirsiniz) ama iyi bir yol IQ grafiğini kontrol etmektir.

![](<../../.gitbook/assets/image (788).png>)

* **AM'yi tespit etme**: IQ grafiğinde örneğin **2 daire** (muhtemelen biri 0'da ve diğeri farklı bir amplitüde) görünüyorsa, bu bir AM sinyali anlamına gelebilir. Bunun nedeni, IQ grafiğinde 0 ile daire arasındaki mesafenin sinyalin amplitüdü olmasıdır, bu nedenle farklı amplitüdlere sahip olmanın görselleştirilmesi kolaydır.
* **PM'yi tespit etme**: Önceki resimde olduğu gibi, eğer birbirleriyle ilişkili olmayan küçük daireler bulursanız, bu muhtemelen bir faz modülasyonunun kullanıldığını gösterir. Bunun nedeni, IQ grafiğinde nokta ile 0,0 arasındaki açının sinyalin fazı olmasıdır, bu da 4 farklı fazın kullanıldığı anlamına gelir.
* Bilginin, bir fazın değişmesi gerçeğinde gizli olduğunu ve fazın kendisinde değilse, farklı fazların net bir şekilde ayrılmadığını unutmayın.
* **FM'yi tespit etme**: IQ'nun frekansları tanımlamak için bir alanı yoktur (merkeze olan mesafe amplitüd ve açı fazdır).\
Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde sadece bir daire görmelisiniz**.\
Ayrıca, farklı bir frekans IQ grafiğinde **daire boyunca bir hızlanma ile "temsil edilir"** (bu nedenle SysDigger'da sinyali seçtiğinizde IQ grafiği doldurulur, eğer oluşturulan dairede bir hızlanma veya yön değişikliği bulursanız bu FM olabilir):

## AM Örneği

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM'yi açığa çıkarma

#### Zarfı kontrol etme

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ile AM bilgilerini kontrol ederken sadece **zarfı** inceleyerek farklı net amplitüd seviyeleri görebilirsiniz. Kullanılan sinyal, AM'de bilgi gönderen darbeler gönderiyor, bir darbenin görünümü şöyle:

![](<../../.gitbook/assets/image (590).png>)

Ve bu, dalga formuyla sembolün bir kısmının görünümüdür:

![](<../../.gitbook/assets/image (734).png>)

#### Histogramı kontrol etme

Bilgi bulunan **tüm sinyali** seçebilir, **Amplitüd** modunu ve **Seçim**'i seçebilir ve **Histogram**'a tıklayabilirsiniz. 2 net seviyenin yalnızca bulunduğunu gözlemleyebilirsiniz.

![](<../../.gitbook/assets/image (264).png>)

Örneğin, bu AM sinyalinde Amplitüd yerine Frekansı seçerseniz sadece 1 frekans bulursunuz (frekans modülasyonunda bilgi sadece 1 frekans kullanıyorsa bu mümkün değildir).

![](<../../.gitbook/assets/image (732).png>)

Eğer birçok frekans bulursanız, bu muhtemelen bir FM olmayacaktır, sinyal frekansı sadece kanal nedeniyle değiştirilmiş olabilir.

#### IQ ile

Bu örnekte, **büyük bir daire** olduğunu ama aynı zamanda **merkezde birçok nokta** olduğunu görebilirsiniz.

![](<../../.gitbook/assets/image (222).png>)

### Sembol Hızını Alma

#### Bir sembolle

Bulduğunuz en küçük sembolü seçin (böylece sadece 1 olduğundan emin olursunuz) ve "Seçim frekansı"nı kontrol edin. Bu durumda 1.013kHz (yani 1kHz) olacaktır.

![](<../../.gitbook/assets/image (78).png>)

#### Bir grup sembolle

Seçtiğiniz sembol sayısını da belirtebilir ve SigDigger 1 sembolün frekansını hesaplayacaktır (seçilen sembol sayısı arttıkça muhtemelen daha iyi olacaktır). Bu senaryoda 10 sembol seçtim ve "Seçim frekansı" 1.004 kHz:

![](<../../.gitbook/assets/image (1008).png>)

### Bitleri Alma

Bunun bir **AM modüle edilmiş** sinyal olduğunu ve **sembol hızını** bulduğunuzu (ve bu durumda yukarı bir şeyin 1 ve aşağı bir şeyin 0 anlamına geldiğini) bildiğinizde, sinyalde kodlanmış **bitleri elde etmek** çok kolaydır. Bu nedenle, bilgiyi içeren sinyali seçin ve örnekleme ve karar verme ayarlarını yapılandırın ve örnekle butonuna basın (lütfen **Amplitüd**'ün seçili olduğundan, keşfedilen **Sembol hızının** yapılandırıldığından ve **Gadner saat geri kazanımının** seçildiğinden emin olun):

![](<../../.gitbook/assets/image (965).png>)

* **Seçim aralıklarına senkronize ol** demek, daha önce sembol hızını bulmak için aralıklar seçtiyseniz, o sembol hızının kullanılacağı anlamına gelir.
* **Manuel** demek, belirtilen sembol hızının kullanılacağı anlamına gelir.
* **Sabit aralık seçimi** ile seçilmesi gereken aralık sayısını belirtirsiniz ve bu aralıklardan sembol hızını hesaplar.
* **Gadner saat geri kazanımı** genellikle en iyi seçenektir, ancak yine de bazı yaklaşık sembol hızını belirtmeniz gerekir.

Örnekleme butonuna bastığınızda bu görünür:

![](<../../.gitbook/assets/image (644).png>)

Artık SigDigger'ın **bilgi taşıyan seviyenin aralığını** anlaması için **alt seviyeye** tıklayıp en yüksek seviyeye kadar basılı tutmanız gerekir:

![](<../../.gitbook/assets/image (439).png>)

Eğer örneğin **4 farklı amplitüd seviyesi** olsaydı, **Sembol başına bit sayısını 2** olarak yapılandırmanız ve en küçüğünden en büyüğüne kadar seçmeniz gerekirdi.

Son olarak, **Zoom**'u **artırarak** ve **Satır boyutunu** değiştirerek bitleri görebilirsiniz (ve tüm bitleri almak için hepsini seçip kopyalayabilirsiniz):

![](<../../.gitbook/assets/image (276).png>)

Eğer sinyalin sembol başına 1'den fazla biti varsa (örneğin 2), SigDigger **hangi sembolün** 00, 01, 10, 11 olduğunu bilmenin bir yoluna sahip değildir, bu nedenle her birini temsil etmek için farklı **gri tonları** kullanacaktır (ve eğer bitleri kopyalarsanız **0'dan 3'e kadar** sayılar kullanacaktır, bunları işlemeniz gerekecektir).

Ayrıca, **Manchester** gibi **kodlamalar** kullanın ve **yukarı+aşağı** **1 veya 0** olabilir ve bir aşağı+yukarı 1 veya 0 olabilir. Bu durumlarda, elde edilen yukarıları (1) ve aşağıları (0) **işleyerek** 01 veya 10 çiftlerini 0 veya 1 olarak değiştirmelisiniz.

## FM Örneği

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM'yi açığa çıkarma

#### Frekansları ve dalga formunu kontrol etme

FM'de modüle edilmiş bilgi gönderen sinyal örneği:

![](<../../.gitbook/assets/image (725).png>)

Önceki resimde, **2 frekansın kullanıldığını** oldukça iyi gözlemleyebilirsiniz, ancak **dalga formunu** gözlemlediğinizde **2 farklı frekansı doğru bir şekilde tanımlayamıyor olabilirsiniz**:

![](<../../.gitbook/assets/image (717).png>)

Bu, sinyali her iki frekansta da yakaladığım için, bu nedenle biri yaklaşık olarak diğerinin negatifidir:

![](<../../.gitbook/assets/image (942).png>)

Eğer senkronize frekans **bir frekansa diğerine göre daha yakınsa**, iki farklı frekansı kolayca görebilirsiniz:

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### Histogramı kontrol etme

Bilgi içeren sinyalin frekans histogramını kontrol ettiğinizde, kolayca 2 farklı sinyal görebilirsiniz:

![](<../../.gitbook/assets/image (871).png>)

Bu durumda, **Amplitüd histogramını** kontrol ederseniz, **sadece bir amplitüd** bulursunuz, bu nedenle **AM olamaz** (eğer birçok amplitüd bulursanız, bu sinyalin kanal boyunca güç kaybetmiş olabileceği anlamına gelebilir):

![](<../../.gitbook/assets/image (817).png>)

Ve bu, faz modülasyonunun olmadığını çok net bir şekilde gösteren faz histogramı olacaktır:

![](<../../.gitbook/assets/image (996).png>)

#### IQ ile

IQ'nun frekansları tanımlamak için bir alanı yoktur (merkeze olan mesafe amplitüd ve açı fazdır).\
Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde sadece bir daire görmelisiniz**.\
Ayrıca, farklı bir frekans IQ grafiğinde **daire boyunca bir hızlanma ile "temsil edilir"** (bu nedenle SysDigger'da sinyali seçtiğinizde IQ grafiği doldurulur, eğer oluşturulan dairede bir hızlanma veya yön değişikliği bulursanız bu FM olabilir):

![](<../../.gitbook/assets/image (81).png>)

### Sembol Hızını Alma

Sembolleri taşıyan frekansları bulduktan sonra, sembol hızını almak için **AM örneğinde kullanılan aynı tekniği** kullanabilirsiniz.

### Bitleri Alma

Sinyalin **frekansa modüle edildiğini** ve **sembol hızını** bulduktan sonra, bitleri almak için **AM örneğinde kullanılan aynı tekniği** kullanabilirsiniz.

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek hacking ipuçlarını paylaşın.

</details>
{% endhint %}
