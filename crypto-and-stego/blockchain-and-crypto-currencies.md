<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


## Temel Kavramlar

- **Akıllı Sözleşmeler**, belirli koşullar sağlandığında blok zincirinde çalışan programlar olarak tanımlanır ve aracı olmadan anlaşma yürütme işlemlerini otomatikleştirir.
- **Merkezi Olmayan Uygulamalar (dApps)**, akıllı sözleşmelere dayanan, kullanıcı dostu bir ön uç ve şeffaf, denetlenebilir bir arka uç içeren uygulamalardır.
- **Tokenlar ve Coinler**, coinlerin dijital para olarak hizmet verirken, tokenların belirli bağlamlarda değer veya sahiplik temsil ettiği farklılık gösterir.
- **Fayda Tokenları**, hizmetlere erişim sağlarken, **Güvenlik Tokenları** varlık sahipliğini belirtir.
- **DeFi**, merkezi otoritelere ihtiyaç duymadan finansal hizmetler sunan Decentralized Finance'ı ifade eder.
- **DEX** ve **DAO'lar**, sırasıyla Merkezi Olmayan Borsa Platformları ve Merkezi Olmayan Otonom Organizasyonlar anlamına gelir.

## Uzlaşma Mekanizmaları

Uzlaşma mekanizmaları, blok zincirinde güvenli ve kabul edilen işlem doğrulamalarını sağlar:
- **Proof of Work (PoW)**, işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token tutmasını gerektirir ve PoW'a kıyasla enerji tüketimini azaltır.

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon transferini içerir. İşlemler dijital imzalar aracılığıyla doğrulanır ve yalnızca özel anahtar sahibi transferleri başlatabilir.

#### Ana Bileşenler:

- **Çoklu İmza İşlemleri**, bir işlemi yetkilendirmek için birden fazla imza gerektirir.
- İşlemler, **girişler** (fon kaynağı), **çıkışlar** (hedef), **ücretler** (madencilere ödenir) ve **scriptler** (işlem kuralları)den oluşur.

### Lightning Ağı

Birden fazla işlemi bir kanal içinde gerçekleştirerek Bitcoin'in ölçeklenebilirliğini artırmayı amaçlar ve yalnızca son durumu blok zincirine yayınlar.

## Bitcoin Gizlilik Endişeleri

**Ortak Giriş Sahipliği** ve **UTXO Değişim Adresi Tespiti** gibi gizlilik saldırıları, işlem desenlerini sömürür. **Karıştırıcılar** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını belirsizleştirerek anonimliği artırır.

## Anonim Olarak Bitcoin Edinme

Yöntemler arasında nakit işlemler, madencilik ve karıştırıcı kullanımı bulunur. **CoinJoin**, izlenebilirliği karmaşıklaştırmak için birden fazla işlemi karıştırırken, **PayJoin**, gizlilik düzeyini artırmak için CoinJoin'leri normal işlemler gibi gösterir.


# Bitcoin Gizlilik Saldırıları

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında, işlemlerin gizliliği ve kullanıcıların anonimliği genellikle endişe konularıdır. İşte saldırganların Bitcoin gizliliğini tehlikeye atabileceği birkaç yaygın yöntemin basitleştirilmiş bir genel bakışı.

## **Ortak Giriş Sahipliği Varsayımı**

Farklı kullanıcılara ait girişlerin tek bir işlemde birleştirilmesi genellikle karmaşık olduğu için nadirdir. Bu nedenle, **aynı işlemdeki iki giriş adresinin genellikle aynı sahibe ait olduğu varsayılır**.

## **UTXO Değişim Adresi Tespiti**

Bir UTXO veya **Harcanmamış İşlem Çıktısı**, bir işlemde tamamen harcanmalıdır. Eğer sadece bir kısmı başka bir adrese gönderilirse, geri kalanı yeni bir değişim adresine gider. Gözlemciler, bu yeni adresin gönderene ait olduğunu varsayabilir ve gizliliği tehlikeye atabilir.

### Örnek
Bu durumu hafifletmek için karıştırma hizmetleri veya birden fazla adres kullanmak, sahipliği belirsizleştirmeye yardımcı olabilir.

## **Sosyal Ağlar ve Forumlarla İlgili Bilgilerin Ortaya Çıkması**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır, bu da adresi sahibiyle ilişkilendirmeyi **kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler grafikler halinde görselleştirilebilir ve fon akışına dayanarak kullanıcılar arasında potansiyel bağlantıları ortaya çıkarabilir.

## **Gereksiz Giriş Heuristiği (Optimal Değişim Heuristiği)**

Bu heuristik, birden fazla giriş ve çıkışa sahip işlemleri analiz ederek değişimi gönderene dönen çıktının hangisi olduğunu tahmin etmeye dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Zorunlu Adres Kullanımı**

Saldırganlar, daha önce kullanılan adreslere küçük miktarlarda gönderim yapabilir ve umut ederler ki alıcı, bu miktarları gelecekteki işlemlerde diğer girdilerle birleştirerek adresleri birbirine bağlar.

### Doğru Cüzdan Davranışı
Bu gizlilik sızıntısını önlemek için cüzdanlar, zaten kullanılmış boş adreslere gelen paraları kullanmamalıdır.

## **Diğer Blockchain Analiz Teknikleri**

- **Tam Ödeme Miktarları:** Değişiklik olmadan gerçekleşen işlemler, muhtemelen aynı kullanıcıya ait iki adres arasında gerçekleşir.
- **Yuvarlak Sayılar:** Bir işlemdeki yuvarlak bir sayı, bir ödeme olduğunu gösterir ve yuvarlanmayan çıktı muhtemelen değişikliktir.
- **Cüzdan Parmak İzi:** Farklı cüzdanlar benzersiz işlem oluşturma desenlerine sahiptir, bu da analistlerin kullanılan yazılımı ve potansiyel olarak değişiklik adresini belirlemelerine olanak sağlar.
- **Miktar ve Zaman Korelasyonları:** İşlem zamanlarını veya miktarlarını açıklamak, işlemlerin izlenebilir olmasına neden olabilir.

## **Trafik Analizi**

Ağ trafiğini izleyerek saldırganlar, kullanıcı gizliliğini tehlikeye atarak işlemleri veya blokları IP adresleriyle ilişkilendirebilirler. Bu özellikle bir kuruluşun birçok Bitcoin düğümü işletmesi durumunda geçerlidir, çünkü bu durumda işlemleri izleme yetenekleri artar.

## Daha Fazlası
Gizlilik saldırıları ve savunmaları için kapsamlı bir liste için [Bitcoin Wiki'deki Bitcoin Gizliliği](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.


# Anonim Bitcoin İşlemleri

## Bitcoins'i Anonim Olarak Nasıl Elde Edilir

- **Nakit İşlemler**: Nakit aracılığıyla bitcoin edinme.
- **Nakit Alternatifleri**: Hediye kartları satın almak ve bunları çevrimiçi olarak bitcoin'e dönüştürmek.
- **Madencilik**: Bitcoin kazanmanın en gizli yöntemi madencilik yapmaktır, özellikle yalnız yapıldığında, çünkü madencilik havuzları madencinin IP adresini bilebilir. [Madencilik Havuzları Bilgisi](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık**: Teorik olarak, bitcoin çalmak başka bir yöntem olabilir, ancak bu yasa dışıdır ve önerilmez.

## Karıştırma Hizmetleri

Bir karıştırma hizmeti kullanarak bir kullanıcı, **bitcoin gönderebilir** ve **farklı bitcoinler alabilir**, bu da orijinal sahibini izlemeyi zorlaştırır. Bununla birlikte, bu, hizmetin günlükleri tutmamasına ve gerçekten bitcoinleri geri vermesine güven gerektirir. Alternatif karıştırma seçenekleri arasında Bitcoin casinoları bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcıların birden fazla işlemini birleştirerek girişleri çıktılarla eşleştirmeye çalışan herhangi bir kişinin işlemi karmaşıklaştırır. Etkili olmasına rağmen, benzersiz giriş ve çıkış boyutlarına sahip işlemler hala izlenebilir olabilir.

CoinJoin kullanılmış olabilecek örnek işlemler şunları içerir: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Ethereum için benzer bir hizmet için [Tornado Cash](https://tornado.cash) adresine göz atın, bu hizmet madencilerin fonlarıyla işlemleri anonimleştirir.

## PayJoin

CoinJoin'in bir türevi olan **PayJoin** (veya P2EP), iki taraf arasındaki (örneğin, bir müşteri ve bir satıcı) işlemi, CoinJoin'in karakteristik eşit çıktıları olmadan normal bir işlem gibi gizler. Bu, tespit etmesi son derece zorlaştırır ve işlem gözetim kuruluşları tarafından kullanılan ortak-giriş-sahipliği heuristiğini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Yukarıdaki gibi işlemler PayJoin olabilir ve standart bitcoin işlemlerinden ayırt edilemeyerek gizliliği artırabilir.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde bozabilir**, bu da işlem gizliliği arayışında umut verici bir gelişme olarak kabul edilir.


# Kripto Paralarda Gizlilik için En İyi Uygulamalar

## **Cüzdan Senkronizasyon Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanları blok zinciriyle senkronize etmek önemlidir. İki yöntem öne çıkar:

- **Tam düğüm**: Tüm blok zincirini indirerek tam bir düğüm, maksimum gizlilik sağlar. Yapılan tüm işlemler yerel olarak depolanır, bu da saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkansız hale getirir.
- **İstemci tarafı blok filtreleme**: Bu yöntem, blok zincirinde her blok için filtreler oluşturmayı içerir, böylece cüzdanlar kullanıcının ilgili işlemleri belirleyebilir ve özel ilgi alanlarını ağ gözlemcilerine açıklamadan. Hafif cüzdanlar bu filtreleri indirir, kullanıcının adresleriyle eşleşme bulunduğunda yalnızca tam blokları alır.

## **Anonimlik için Tor Kullanımı**

Bitcoin'in eşler arası bir ağ üzerinde çalıştığı göz önüne alındığında, ağla etkileşimde bulunurken IP adresinizi gizlemek için Tor kullanmanız önerilir, gizliliği artırır.

## **Adres Tekrarını Önleme**

Gizliliği korumak için her işlem için yeni bir adres kullanmak önemlidir. Adres tekrarı, işlemleri aynı varlıkla ilişkilendirerek gizliliği tehlikeye atabilir. Modern cüzdanlar, tasarımlarıyla adres tekrarını teşvik etmez.

## **İşlem Gizliliği Stratejileri**

- **Birden fazla işlem**: Bir ödemeyi birkaç işleme bölmek, işlem miktarını belirsizleştirerek gizlilik saldırılarını engelleyebilir.
- **Değişiklikten kaçınma**: Değişiklik çıktıları gerektirmeyen işlemleri tercih etmek, değişiklik tespit yöntemlerini bozarak gizliliği artırır.
- **Birden fazla değişiklik çıktısı**: Değişiklikten kaçınmak mümkün olmadığında, birden fazla değişiklik çıktısı oluşturmak yine de gizliliği artırır.

# **Monero: Anonimliğin Işığı**

Monero, dijital işlemlerde mutlak anonimliğe ihtiyacı karşılar ve gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas ve İşlemler**

## **Gas'ı Anlama**

Gas, Ethereum'da işlemleri gerçekleştirmek için gereken hesaplama çabasını **gwei** cinsinden ölçer. Örneğin, 2.310.000 gwei (veya 0.00231 ETH) maliyeti olan bir işlem, bir gaz limiti ve bir temel ücret içerir ve madencileri teşvik etmek için bir bahşiş içerir. Kullanıcılar, fazla ödeme yapmamak için maksimum ücreti belirleyebilir ve fazlası iade edilir.

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemler gönderen ve alıcı olmak üzere iki tarafı içerir, bu adresler kullanıcı veya akıllı sözleşme adresleri olabilir. İşlemler bir ücret gerektirir ve madencilik yapılmalıdır. Bir işlemdeki temel bilgiler alıcı, gönderenin imzası, değer, isteğe bağlı veriler, gaz limiti ve ücretleri içerir. Özellikle, gönderenin adresi imzadan türetilir, bu da işlem verilerinde adresin gereksiz olmasını sağlar.

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliği önceliklendiren herkesin kripto paralarla etkileşime girmek istemesi için temel oluşturur.


## Referanslar

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi paylaşmak için PR göndererek [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
