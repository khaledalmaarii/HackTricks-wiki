# macOS Bellek Dökümü

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}


## Bellek Artifaktları

### Takas Dosyaları

Takas dosyaları, `/private/var/vm/swapfile0` gibi, **fiziksel bellek dolduğunda önbellek olarak** hizmet eder. Fiziksel bellek dolduğunda, veriler bir takas dosyasına aktarılır ve ihtiyaç duyulduğunda tekrar fiziksel belleğe getirilir. swapfile0, swapfile1 gibi birden fazla takas dosyası bulunabilir.

### Hibernasyon Görüntüsü

`/private/var/vm/sleepimage` konumundaki dosya, **hibernasyon modunda** kritik öneme sahiptir. **OS X hibernasyona geçtiğinde bellek verileri bu dosyada saklanır**. Bilgisayar uyandığında, sistem bu dosyadan bellek verilerini alır ve kullanıcının kaldığı yerden devam etmesine olanak tanır.

Modern MacOS sistemlerinde, bu dosyanın genellikle güvenlik nedenleriyle şifreli olduğunu ve kurtarmanın zor olduğunu belirtmek gerekir.

* sleepimage için şifrelemenin etkin olup olmadığını kontrol etmek için `sysctl vm.swapusage` komutu çalıştırılabilir. Bu, dosyanın şifreli olup olmadığını gösterecektir.

### Bellek Baskı Günlükleri

MacOS sistemlerinde başka bir önemli bellekle ilgili dosya **bellek baskı günlüğü**dür. Bu günlükler `/var/log` konumunda bulunur ve sistemin bellek kullanımı ve baskı olayları hakkında ayrıntılı bilgi içerir. Bellekle ilgili sorunları teşhis etmek veya sistemin zamanla belleği nasıl yönettiğini anlamak için özellikle yararlı olabilir.

## osxpmem ile bellek dökümü

Bir MacOS makinesinde belleği dökmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanabilirsiniz.

**Not**: Aşağıdaki talimatlar yalnızca Intel mimarisine sahip Mac'ler için geçerlidir. Bu araç artık arşivlenmiştir ve son sürümü 2017'de çıkmıştır. Aşağıdaki talimatlarla indirilen ikili dosya, 2017'de Apple Silicon olmadığı için Intel yongalarını hedef alır. arm64 mimarisi için ikili dosyayı derlemek mümkün olabilir, ancak bunu kendiniz denemeniz gerekecek.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Eğer bu hatayı bulursanız: `osxpmem.app/MacPmem.kext yüklenemedi - (libkern/kext) kimlik doğrulama hatası (dosya sahipliği/izinleri); hatalar için sistem/kernel günlüklerini kontrol edin veya kextutil(8) deneyin` Bunu düzeltmek için:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar**, "Güvenlik ve Gizlilik --> Genel" bölümünde **kext'in yüklenmesine izin vererek** düzeltilebilir, sadece **izin verin**.

Ayrıca bu **tek satırlık komutu** uygulamayı indirmek, kext'i yüklemek ve belleği dökmek için kullanabilirsiniz:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
