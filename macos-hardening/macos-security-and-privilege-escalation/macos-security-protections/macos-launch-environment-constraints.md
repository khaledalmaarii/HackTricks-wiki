# macOS Başlatma/Çevre Kısıtlamaları ve Güven Önbelleği

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın**
*
* .

</details>

## Temel Bilgiler

macOS'ta başlatma kısıtlamaları, bir işlemin **nasıl, kim tarafından ve nereden başlatılabileceğini düzenleyerek** güvenliği artırmak için tanıtılmıştır. macOS Ventura'da başlatılan bu kısıtlamalar, **her sistem ikili dosyasını farklı kısıtlama kategorilerine** ayıran bir çerçeve sağlar. Bu kısıtlamalar, sistemdeki her yürütülebilir ikili dosyayı kapsar ve bir **belirli bir ikili dosyanın başlatılması için gereksinimleri belirleyen bir dizi kuralı** içerir. Kurallar, bir ikili dosyanın karşılaması gereken kendi kısıtlamaları, ebeveyn sürecinin karşılaması gereken ebeveyn kısıtlamaları ve diğer ilgili varlıkların uyması gereken sorumlu kısıtlamaları içerir.

Bu mekanizma, macOS Sonoma'dan itibaren üçüncü taraf uygulamalara **Çevre Kısıtlamaları** aracılığıyla da genişletilir ve geliştiricilere uygulamalarını korumak için bir dizi anahtar ve değer belirtme imkanı sağlar.

Başlatma çevresi ve kitaplık kısıtlamalarını, **`launchd` özellik listesi dosyalarında** veya kod imzalama için kullandığınız **ayrı özellik listesi** dosyalarında kaydedebileceğiniz kısıtlama sözlüklerinde tanımlarsınız.

4 tür kısıtlama vardır:

* **Kendi Kısıtlamaları**: Çalışan ikili dosyaya uygulanan kısıtlamalar.
* **Ebeveyn Süreç Kısıtlamaları**: İşlemin ebeveyn sürecine uygulanan kısıtlamalar (örneğin **`launchd`** bir XP hizmeti çalıştırıyor).
* **Sorumlu Kısıtlamalar**: XPC iletişiminde hizmeti çağıran sürece uygulanan kısıtlamalar.
* **Kitaplık yükleme kısıtlamaları**: Yüklenebilecek kodu seçici olarak tanımlamak için kitaplık yükleme kısıtlamalarını kullanın.

Bir işlem başka bir işlemi başlatmaya çalıştığında - `execve(_:_:_:)` veya `posix_spawn(_:_:_:_:_:_:)` çağrısı yaparak - işletim sistemi, **yürütülebilir** dosyanın **kendi kısıtlamasını karşıladığını** kontrol eder. Ayrıca, **ebeveyn sürecin** yürütülebilir dosyanın **ebeveyn kısıtlamasını karşıladığını** ve **sorumlu sürecin** yürütülebilir dosyanın **sorumlu süreç kısıtlamasını karşıladığını** kontrol eder. Bu başlatma kısıtlamalarından herhangi biri karşılanmazsa, işletim sistemi programı çalıştırmaz.

Bir kitaplık yüklerken kitaplık kısıtlamasının **herhangi bir bölümü doğru değilse**, işleminiz kitaplığı **yüklemiyor**.

## LC Kategorileri

Bir LC, **gerçekler** ve **mantıksal işlemler** (ve, veya..) içeren bir yapıdır.

[**Bir LC'nin kullanabileceği gerçekler belgelenmiştir**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Örneğin:

* is-init-proc: İkili dosyanın işletim sisteminin başlatma işlemi (`launchd`) olması gerekip gerekmediğini belirten bir Boolean değeri.
* is-sip-protected: İkili dosyanın System Integrity Protection (SIP) tarafından korunan bir dosya olup olmadığını belirten bir Boolean değeri.
* `on-authorized-authapfs-volume:` İşletim sisteminin, yetkilendirilmiş, doğrulanmış bir APFS biriminden yürütülebilir dosyayı yükleyip yüklemediğini belirten bir Boolean değeri.
* `on-authorized-authapfs-volume`: İşletim sisteminin, yetkilendirilmiş, doğrulanmış bir APFS biriminden yürütülebilir dosyayı yükleyip yüklemediğini belirten bir Boolean değeri.
* Cryptexes birimi
* `on-system-volume:` İşletim sisteminin, şu anda başlatılan sistem biriminden yürütülebilir dosyayı yükleyip yüklemediğini belirten bir Boolean değeri.
* /System içinde...
* ...

Bir Apple ikili dosyası imzalandığında, onu bir LC kategorisine **görevlendirir** ve **güven önbelleği** içinde yer alır.

* **iOS 16 LC kategorileri** [**burada tersine çevrilmiş ve belgelenmiştir**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Mevcut **LC kategorileri (macOS 14** - Somona) tersine çevrilmiş ve [**açıklamaları burada bulunabilir**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Örneğin Kategori 1:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Sistem veya Cryptexes biriminde olmalıdır.
* `launch-type == 1`: Sistem hizmeti olmalıdır (LaunchDaemons'ta plist olarak).
* `validation-category == 1`: İşletim sistemi yürütülebilir dosyası.
* `is-init-proc`: Launchd

### LC Kategorilerini Tersine Çevirme

Daha fazla bilgi için [**burada**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints) bulabilirsiniz, ancak temel olarak, bunlar **AMFI (AppleMobileFileIntegrity)** içinde tanımlanır, bu nedenle **KEXT**'i almak için Kernel Development Kit'i indirmeniz gerekmektedir. **`kConstraintCategory`** ile başlayan semboller ilginç olanlardır. Bunları çıkararak, DER (ASN.1) kodlu bir akış elde edersiniz ve bunu [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) veya python-asn1 kütüphanesi ve `dump.py` betiği olan [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) ile çözmeniz gerekecektir, bu size daha anlaşılabilir bir dize verecektir.

## Ortam Kısıtlamaları

Bunlar, **üçüncü taraf uygulamalarında** yapılandırılan Başlatma Kısıtlamalarıdır. Geliştirici, uygulamasının erişimini kısıtlamak için kullanılacak **gerçekleri** ve **mantıksal operandları** seçebilir.

Bir uygulamanın Ortam Kısıtlamalarını şu şekilde sıralayabilirsiniz:
```bash
codesign -d -vvvv app.app
```
## Güven Önbelleği

**macOS**'ta birkaç güven önbelleği bulunur:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

Ve iOS'ta ise **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** olarak görünmektedir.

{% hint style="warning" %}
Apple Silicon cihazlarda çalışan macOS'ta, bir Apple imzalı ikili dosya güven önbelleğinde bulunmuyorsa, AMFI yüklemeyi reddedecektir.
{% endhint %}

### Güven Önbelleklerini Sıralama

Önceki güven önbelleği dosyaları **IMG4** ve **IM4P** formatındadır, IM4P IMG4 formatının yük bölümüdür.

Veritabanlarının yükünü çıkarmak için [**pyimg4**](https://github.com/m1stadev/PyIMG4) kullanabilirsiniz:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Başka bir seçenek, [**img4tool**](https://github.com/tihmstar/img4tool) adlı aracı kullanmaktır, bu araç eski bir sürüm olsa bile M1'de çalışacak ve doğru konumlara yüklerseniz x86\_64 için çalışacaktır).

Şimdi, bilgileri okunabilir bir formatta almak için [**trustcache**](https://github.com/CRKatri/trustcache) adlı aracı kullanabilirsiniz:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Güven önbelleği aşağıdaki yapıyı takip eder, bu yüzden **LC kategorisi 4. sütundadır**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Aşağıdaki betik gibi bir betik kullanabilirsiniz: [**bu betik**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) verileri çıkarmak için.

Bu verilerden, **`0` başlatma kısıtlamaları değerine sahip** Uygulamaları kontrol edebilirsiniz, bunlar kısıtlanmayan uygulamalardır ([**buraya bakın**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) her bir değer için ne olduğu için).

## Saldırı Önlemleri

Başlatma Kısıtlamaları, birçok eski saldırıyı önlemek için kullanılmıştır, **işlemi beklenmedik koşullarda çalıştırmamayı sağlayarak:** Örneğin, beklenmedik konumlardan veya beklenmeyen bir üst işlem tarafından çağrılmamış olmasını sağlar (sadece launchd tarafından başlatılması gerekiyorsa).

Ayrıca, Başlatma Kısıtlamaları aynı zamanda **sürüm düşürme saldırılarını da önler**.

Ancak, yaygın XPC kötüye kullanımlarını, Electron kod enjeksiyonlarını veya kitaplık doğrulaması olmadan dylib enjeksiyonlarını (kitaplıkları yükleyebilen takım kimlikleri bilinmediği sürece) **önlemezler**.

### XPC Daemon Koruması

Sonoma sürümünde, dikkate değer bir nokta, daemon XPC hizmetinin **sorumluluk yapılandırması**dır. XPC hizmeti, bağlanan istemcinin sorumlu olması yerine kendisi için sorumludur. Bu, geri bildirim raporu FB13206884'te belgelenmiştir. Bu yapılandırma hatalı gibi görünebilir, çünkü XPC hizmetiyle belirli etkileşimlere izin verir:

- **XPC Hizmetini Başlatma**: Bir hata olarak kabul edilirse, bu yapılandırma saldırgan kod aracılığıyla XPC hizmetini başlatmaya izin vermez.
- **Etkin Bir Hizmete Bağlanma**: XPC hizmeti zaten çalışıyorsa (muhtemelen orijinal uygulama tarafından etkinleştirilmiş olabilir), buna bağlanmanın engelleri yoktur.

XPC hizmetine kısıtlamalar uygulamak, **potansiyel saldırılar için pencereyi daraltarak** faydalı olabilir, ancak temel endişeyi ele almaz. XPC hizmetinin güvenliğini sağlamak için, bağlanan istemcinin etkili bir şekilde doğrulanması gerekmektedir. Bu, hizmetin güvenliğini sağlamak için tek yöntemdir. Ayrıca, bahsi geçen sorumluluk yapılandırmasının şu anda işlevsel olduğunu ve amaçlanan tasarımla uyumlu olmayabileceğini belirtmek önemlidir.

### Electron Koruması

Uygulamanın **LaunchService tarafından açılması gerektiği** (ebeveyn kısıtlamalarında). Bu, **`open`** kullanılarak (çevre değişkenleri ayarlanabilir) veya **Launch Services API** kullanılarak (çevre değişkenleri belirtilebilir) başarılabilmektedir.

## Referanslar

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u** takip edin.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile PR göndererek paylaşın**
*
* .

</details>
