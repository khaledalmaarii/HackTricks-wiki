# macOS AppleFS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple'a Ait Dosya Sistemi (APFS)

**Apple Dosya Sistemi (APFS)**, Hiyerarşik Dosya Sistemi Artı (HFS+) yerine geçmek üzere tasarlanmış modern bir dosya sistemidir. Geliştirilmesi, **geliştirilmiş performans, güvenlik ve verimlilik** ihtiyacından kaynaklanmıştır.

APFS'nin bazı dikkat çekici özellikleri şunlardır:

1. **Alan Paylaşımı**: APFS, bir fiziksel cihazda **aynı temel boş depolamayı paylaşan birden fazla hacme** izin verir. Bu, hacimlerin manuel yeniden boyutlandırma veya yeniden bölümleme gerektirmeden dinamik olarak büyüyüp küçülmesine olanak tanıyarak daha verimli alan kullanımını sağlar.
1. Bu, dosya disklerindeki geleneksel bölümlerle karşılaştırıldığında, **APFS'de farklı bölümlerin (hacimlerin) tüm disk alanını paylaştığı** anlamına gelir; oysa normal bir bölüm genellikle sabit bir boyuta sahipti.
2. **Anlık Görüntüler**: APFS, **okunabilir** olan, dosya sisteminin belirli bir zamandaki anlık görüntülerini **oluşturmayı destekler**. Anlık görüntüler, minimal ek depolama alanı tüketerek verimli yedeklemeler ve kolay sistem geri yüklemeleri sağlar ve hızlı bir şekilde oluşturulabilir veya geri alınabilir.
3. **Klonlar**: APFS, **orijinal dosya ile aynı depolamayı paylaşan dosya veya dizin klonları oluşturabilir**; bu, ya klon ya da orijinal dosya değiştirilene kadar geçerlidir. Bu özellik, depolama alanını çoğaltmadan dosya veya dizinlerin kopyalarını oluşturmanın verimli bir yolunu sunar.
4. **Şifreleme**: APFS, **tam disk şifrelemesini** yanı sıra dosya ve dizin başına şifrelemeyi de **yerel olarak destekler**, bu da farklı kullanım senaryolarında veri güvenliğini artırır.
5. **Çökme Koruması**: APFS, ani güç kaybı veya sistem çökmesi durumlarında dosya sistemi tutarlılığını sağlamak için **yazma sırasında kopyalama meta veri şemasını** kullanır ve veri bozulma riskini azaltır.

Genel olarak, APFS, Apple cihazları için daha modern, esnek ve verimli bir dosya sistemi sunar ve geliştirilmiş performans, güvenilirlik ve güvenliğe odaklanır.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` hacmi **`/System/Volumes/Data`** dizinine monte edilmiştir (bunu `diskutil apfs list` ile kontrol edebilirsiniz).

Firmlinklerin listesi **`/usr/share/firmlinks`** dosyasında bulunabilir.
```bash
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
