# macOS Bellek Dökme

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## Bellek Kalıntıları

### Takas Dosyaları

`/private/var/vm/swapfile0` gibi takas dosyaları, **fiziksel bellek dolu olduğunda önbellek olarak hizmet verir**. Fiziksel bellekte daha fazla yer olmadığında, veriler takas dosyasına aktarılır ve ihtiyaç duyulduğunda fiziksel belleğe geri getirilir. swapfile0, swapfile1 gibi isimlerle birden fazla takas dosyası bulunabilir.

### Uyku Görüntüsü

`/private/var/vm/sleepimage` konumundaki dosya, **uyku modunda** kritiktir. **OS X uyku modundayken bellek verileri bu dosyada depolanır**. Bilgisayar uyandığında, sistem bellek verilerini bu dosyadan alır ve kullanıcıya kaldığı yerden devam etme olanağı sağlar.

Modern MacOS sistemlerinde, bu dosyanın genellikle güvenlik nedenleriyle şifrelendiğini ve kurtarmanın zor olduğunu belirtmek önemlidir.

* Uyku görüntüsü için şifrelemenin etkin olup olmadığını kontrol etmek için `sysctl vm.swapusage` komutu çalıştırılabilir. Bu, dosyanın şifrelenip şifrelenmediğini gösterecektir.

### Bellek Basıncı Günlükleri

MacOS sistemlerindeki bir diğer önemli bellek ile ilgili dosya **bellek basıncı günlükleri**dir. Bu günlükler `/var/log` konumunda bulunur ve sistem bellek kullanımı ve basınç olayları hakkında detaylı bilgiler içerir. Bellek ile ilgili sorunları teşhis etmek veya sistem belleğin zaman içinde nasıl yönetildiğini anlamak için oldukça yararlı olabilirler.

## osxpmem ile belleği dökme

Bir MacOS makinesinde belleği dökmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanabilirsiniz.

**Not**: Aşağıdaki talimatlar yalnızca Intel mimarisine sahip Mac'ler için çalışacaktır. Bu araç artık arşivlenmiştir ve son sürümü 2017'de yayınlanmıştır. Aşağıdaki talimatlarla indirilen ikili dosya, Apple Silicon'in 2017'de mevcut olmadığı için Intel çipleri hedef almaktadır. arm64 mimarisi için ikili dosyayı derlemek mümkün olabilir ancak bunu kendiniz denemelisiniz.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Eğer bu hatayı bulursanız: `osxpmem.app/MacPmem.kext yüklenemedi - (libkern/kext) kimlik doğrulama hatası (dosya sahipliği/izinleri); hatalar için sistem/kernel günlüklerini kontrol edin veya kextutil(8)'i deneyin` Bunun düzeltilmesi için şunu yapabilirsiniz:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar**, sadece "Güvenlik ve Gizlilik --> Genel" bölümünde **kext'in yüklenmesine izin vererek** düzeltilebilir, sadece **izin verin**.

Uygulamayı indirmek, kext'i yüklemek ve belleği dökmek için bu **oneliner'ı** da kullanabilirsiniz:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize** edilip edilmediğini kontrol etmek için **ücretsiz** işlevler sunan **karanlık ağ** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
