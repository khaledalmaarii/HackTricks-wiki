# macOS Proces Kötüye Kullanımı

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'a katılın!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## MacOS Proses Kötüye Kullanımı

MacOS, diğer işletim sistemleri gibi, **proseslerin etkileşimde bulunması, iletişim kurması ve veri paylaşması** için çeşitli yöntemler ve mekanizmalar sağlar. Bu teknikler, sistem verimli çalışması için önemli olsa da, tehdit aktörleri tarafından **kötü amaçlı faaliyetler gerçekleştirmek** için de kötüye kullanılabilir.

### Kütüphane Enjeksiyonu

Kütüphane Enjeksiyonu, bir saldırganın bir işlemi **kötü amaçlı bir kütüphane yüklemeye zorladığı** bir tekniktir. Enjekte edildikten sonra, kütüphane hedef işlemin bağlamında çalışır ve saldırgana işlemle aynı izinleri ve erişimi sağlar.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Fonksiyon Kancalama

Fonksiyon Kancalama, bir yazılım kodu içindeki **fonksiyon çağrılarını veya mesajları engelleme** işlemidir. Fonksiyonları kancalayarak, bir saldırgan bir işlemin davranışını **değiştirebilir**, hassas verileri gözlemleyebilir veya hatta yürütme akışını kontrol edebilir.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### İşlem Arası İletişim

İşlem Arası İletişim (IPC), ayrı işlemlerin **veri paylaşmasını ve değiş tokuş etmesini** sağlayan farklı yöntemleri ifade eder. IPC, birçok meşru uygulama için temel olmasına rağmen, işlem izolasyonunu altüst etmek, hassas bilgileri sızdırmak veya yetkisiz işlemler gerçekleştirmek için kötüye kullanılabilir.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Electron Uygulamaları Enjeksiyonu

Belirli env değişkenleriyle çalıştırılan Electron uygulamaları, işlem enjeksiyonuna karşı savunmasız olabilir:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Kirli NIB

NIB dosyaları, bir uygulama içindeki kullanıcı arayüzü (UI) öğelerini ve etkileşimlerini tanımlar. Bununla birlikte, NIB dosyaları **keyfi komutlar yürütebilir** ve **Gatekeeper**, bir NIB dosyası değiştirildiyse zaten yürütülen bir uygulamanın yürütülmesini durdurmaz. Bu nedenle, keyfi programların keyfi komutları yürütmesi için kullanılabilirler:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Java Uygulamaları Enjeksiyonu

Belirli java yeteneklerini (örneğin **`_JAVA_OPTS`** env değişkeni) kötüye kullanarak bir java uygulamasının **keyfi kod/komutları** yürütmesi mümkündür.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Net Uygulamaları Enjeksiyonu

.Net uygulamalarına kod enjekte etmek, macOS korumaları gibi çalışma zamanı sertleştirme tarafından korunmayan **.Net hata ayıklama işlevselliğini** kötüye kullanarak mümkündür.

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl Enjeksiyonu

Bir Perl betiğinin keyfi kodu yürütmesi için farklı seçenekleri kontrol edin:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby Enjeksiyonu

Ruby env değişkenlerini kötüye kullanarak keyfi komutları yürütmek de mümkündür:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Python Enjeksiyonu

Eğer **`PYTHONINSPECT`** çevre değişkeni ayarlanmışsa, python işlemi tamamlandığında bir python cli'ye düşer. Ayrıca, etkileşimli bir oturumun başlangıcında yürütülecek bir python betiğini belirtmek için **`PYTHONSTARTUP`** kullanmak da mümkündür.\
Ancak, **`PYTHONINSPECT`** etkileşimli oturumu oluşturduğunda **`PYTHONSTARTUP`** betiği yürütülmeyeceğini unutmayın.

**`PYTHONPATH`** ve **`PYTHONHOME`** gibi diğer çevre değişkenleri de bir python komutunun keyfi kodu yürütmesi için kullanışlı olabilir.

**`pyinstaller`** ile derlenen yürütülebilir dosyalar, gömülü bir python kullanıyor olsalar bile bu çevresel değişkenleri kullanmayacaktır.

{% hint style="danger" %}
Genel olarak, çevre değişkenlerini kötüye kullanarak python'un keyfi kodu yürütmesi için bir yol bulamadım.\
Ancak, çoğu insan, pyhton'u **Hombrew** kullanarak yükler, bu da pyhton'u varsayılan yönetici kullanıcısı için **yazılabilir bir konuma** yükler. Bunu şu şekilde ele geçirebilirsiniz:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Bu kodu çalıştıran herkes, hatta **root** bile olabilir.

## Tespit

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)), **proses enjeksiyonunu tespit edebilen ve engelleyebilen** açık kaynaklı bir uygulamadır:

* **Çevresel Değişkenler** Kullanarak: Aşağıdaki çevresel değişkenlerin varlığını izleyecektir: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** ve **`ELECTRON_RUN_AS_NODE`**
* **`task_for_pid`** çağrılarını kullanarak: Bir işlemin başka bir işlemin **görev bağlantısını almak** istediği zamanı bulmak için kullanılır, bu da işleme kod enjekte etmeyi mümkün kılar.
* **Electron uygulama parametreleri**: Birisi, bir Electron uygulamasını hata ayıklama modunda başlatmak ve böylece kod enjekte etmek için **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** komut satırı argümanlarını kullanabilir.
* **Sembolik bağlantılar** veya **sabit bağlantılar** kullanarak: Genellikle en yaygın kötüye kullanım, **kullanıcı ayrıcalıklarımızla bir bağlantı oluşturmak** ve onu daha yüksek bir ayrıcalık düzeyine **yönlendirmektir**. Hem sabit bağlantılar hem de sembolik bağlantılar için tespit çok basittir. Bağlantıyı oluşturan işlemin hedef dosyadan **farklı bir ayrıcalık düzeyine** sahip olması durumunda bir **uyarı** oluştururuz. Ne yazık ki sembolik bağlantılar için engelleme mümkün değildir, çünkü bağlantının hedefi hakkında bilgiye sahip değiliz. Bu, Apple'ın EndpointSecurity çerçevesinin bir sınırlamasıdır.

### Diğer işlemler tarafından yapılan çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) başka bir işlemin bir işleme kod enjekte ettiğini tespit etmek ve ardından o diğer işlem hakkında bilgi almak için **`task_name_for_pid`** işlevini nasıl kullanabileceğinizi bulabilirsiniz.

Bu işlevi çağırmak için, işlemi çalıştıran kişiyle **aynı uid**'ye veya **root** olmanız gerekmektedir (ve bu, kod enjekte etmek için bir yol değil, sadece işlem hakkında bilgi döndürür).

## Referanslar

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>AWS hackleme yeteneklerinizi sıfırdan kahraman seviyesine çıkarın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi paylaşarak **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek katkıda bulunun.

</details>
