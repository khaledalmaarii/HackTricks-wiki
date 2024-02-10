# macOS AppleFS

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'a katılın!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** katkıda bulunun.

</details>

## Apple Özel Dosya Sistemi (APFS)

**Apple Dosya Sistemi (APFS)**, Hiyerarşik Dosya Sistemi Plus (HFS+) yerine geçmek üzere tasarlanmış modern bir dosya sistemidir. Geliştirilmesi, **daha iyi performans, güvenlik ve verimlilik** ihtiyacıyla gerçekleştirilmiştir.

APFS'nin bazı dikkate değer özellikleri şunlardır:

1. **Alan Paylaşımı**: APFS, birden fazla birimin **aynı fiziksel cihaz üzerindeki boş depolama alanını paylaşmasına** olanak tanır. Bu, birimlerin manuel yeniden boyutlandırma veya yeniden bölümlendirme gerektirmeden dinamik olarak büyüyüp küçülmesine olanak sağlayarak daha verimli alan kullanımını sağlar.
1. Bu, dosya disklerindeki geleneksel bölümlerle karşılaştırıldığında, **APFS'de farklı bölümlerin (birimlerin) tüm disk alanını paylaştığı** anlamına gelir, oysa normal bir bölüm genellikle sabit bir boyuta sahiptir.
2. **Anlık Görüntüler**: APFS, dosya sisteminin **salt okunur, zaman içindeki anlık örneklerini oluşturmayı** destekler. Anlık görüntüler, minimal ek depolama tüketimiyle verimli yedeklemeler ve kolay sistem geri dönüşleri sağlar ve hızlı bir şekilde oluşturulabilir veya geri alınabilir.
3. **Klonlar**: APFS, **aynı depolama alanını paylaşan dosya veya dizin klonları oluşturabilir**. Bu özellik, depolama alanını kopyalamadan dosya veya dizin kopyaları oluşturmanın verimli bir yolunu sağlar.
4. **Şifreleme**: APFS, veri güvenliğini artıran **tam disk şifrelemesini** ve dosya veya dizin bazında şifrelemeyi doğal olarak destekler.
5. **Çökme Koruması**: APFS, dosya sistemi tutarlılığını sağlayan **kopyala-yaz metadata şemasını** kullanır, böylece ani güç kaybı veya sistem çökmeleri durumunda bile veri bozulma riskini azaltır.

Genel olarak, APFS, Apple cihazları için daha modern, esnek ve verimli bir dosya sistemi sunar ve performans, güvenilirlik ve güvenlik konularına odaklanır.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` birimi **`/System/Volumes/Data`** konumuna bağlanır (bunu `diskutil apfs list` komutuyla kontrol edebilirsiniz).

Firmlink'lerin listesi **`/usr/share/firmlinks`** dosyasında bulunabilir.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
**Sol tarafta**, **Sistem birimindeki** dizin yolunu ve **sağ tarafta**, **Veri birimindeki** eşleştiği dizin yolunu görebilirsiniz. Yani, `/library` --> `/system/Volumes/data/library`
