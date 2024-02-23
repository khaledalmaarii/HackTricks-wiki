# macOS İşlem Kötüye Kullanımı

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

- Şirketinizi HackTricks'te reklamını görmek veya HackTricks'i PDF olarak indirmek istiyorsanız [ABONELİK PLANLARI](https://github.com/sponsors/carlospolop)'na göz atın!
- [Resmi PEASS & HackTricks ürünlerini](https://peass.creator-spring.com) edinin
- [The PEASS Family](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel NFT'lerimizi inceleyin
- 💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya Twitter'da bizi takip edin 🐦 [@carlospolopm](https://twitter.com/hacktricks\_live).
- Hacking püf noktalarınızı paylaşarak PR'ler göndererek [HackTricks](https://github.com/carlospolop/hacktricks) ve [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## MacOS İşlem Kötüye Kullanımı

MacOS, diğer işletim sistemleri gibi **işlemlerin etkileşimde bulunması, iletişim kurması ve veri paylaşması** için çeşitli yöntemler ve mekanizmalar sağlar. Bu teknikler, sistemin verimli çalışması için önemli olsa da, tehdit aktörleri tarafından **kötü amaçlı faaliyetler gerçekleştirmek** için kötüye kullanılabilir.

### Kütüphane Enjeksiyonu

Kütüphane Enjeksiyonu, bir saldırganın bir işlemi **zararlı bir kütüphane yüklemeye zorladığı** bir tekniktir. Enjekte edildiğinde, kütüphane hedef işlemin bağlamında çalışır, saldırganı işlemle aynı izinler ve erişimle donatır.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Fonksiyon Hooking

Fonksiyon Hooking, bir yazılım kodu içindeki **fonksiyon çağrılarını veya iletileri engelleme**yi içerir. Fonksiyonları kancalamak, bir saldırganın bir işlemin davranışını **değiştirmesine**, hassas verileri gözlemlemesine veya hatta yürütme akışını kontrol etmesine olanak tanır.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### İşlem Arası İletişim

İşlem Arası İletişim (IPC), ayrı işlemlerin **veri paylaşımı ve değiş tokuşu** yapabileceği farklı yöntemleri ifade eder. IPC, birçok yasal uygulama için temel olmasına rağmen, işlem izolasyonunu alt üst etmek, hassas bilgileri sızdırmak veya yetkisiz eylemler gerçekleştirmek için kötüye kullanılabilir.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Electron Uygulamaları Enjeksiyonu

Belirli çevresel değişkenlerle yürütülen Electron uygulamaları, işlem enjeksiyonuna karşı savunmasız olabilir:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Chromium Enjeksiyonu

`--load-extension` ve `--use-fake-ui-for-media-stream` bayraklarını kullanarak **tarayıcıda adam ortasında saldırı** gerçekleştirmek mümkündür; bu, tuş vuruşlarını, trafiği, çerezleri çalmayı, sayfalara betik enjekte etmeyi sağlar...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Kirli NIB

NIB dosyaları, bir uygulama içindeki kullanıcı arayüzü (UI) öğelerini ve etkileşimlerini tanımlar. Bununla birlikte, NIB dosyaları **keyfi komutlar yürütebilir** ve bir **NIB dosyası değiştirilmişse**, Gatekeeper, zaten yürütülen bir uygulamanın yürütülmesini durduramaz. Bu nedenle, bunlar keyfi programların keyfi komutlarını yürütmek için kullanılabilir:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Java Uygulamaları Enjeksiyonu

Belirli java yeteneklerini (örneğin **`_JAVA_OPTS`** çevresel değişkeni) kötüye kullanarak bir java uygulamasının **keyfi kod/komutlar yürütmesi** mümkündür.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Net Uygulamaları Enjeksiyonu

.Net uygulamalarına kod enjekte etmek, macOS korumaları tarafından (çalışma zamanı sıkılaştırma gibi) korunmayan **.Net hata ayıklama işlevselliğini kötüye kullanarak** mümkündür.

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl Enjeksiyonu

Bir Perl betiğinin keyfi kod yürütmesini sağlamak için farklı seçenekleri kontrol edin:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby Enjeksiyonu

Keyfi betiklerin keyfi kod yürütmesi için ruby çevresel değişkenlerini kötüye kullanmak mümkündür:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Python Enjeksiyonu

Eğer **`PYTHONINSPECT`** çevresel değişkeni ayarlanmışsa, python işlemi tamamlandığında bir python cli'ye düşer. Ayrıca etkileşimli bir oturumun başında yürütülecek bir python betiğini belirtmek için **`PYTHONSTARTUP`** kullanmak da mümkündür.\
Ancak, **`PYTHONSTARTUP`** betiği, **`PYTHONINSPECT`** etkileşimli oturum oluşturduğunda yürütülmeyecektir.

**`PYTHONPATH`** ve **`PYTHONHOME`** gibi diğer çevresel değişkenler de bir python komutunun keyfi kod yürütmesi için kullanışlı olabilir.

**`pyinstaller`** ile derlenen yürütülebilir dosyalar, gömülü bir python kullanıyor olsalar bile bu çevresel değişkenleri kullanmayacaktır.

{% hint style="danger" %}
Genel olarak, çevresel değişkenleri kötüye kullanarak python'un keyfi kod yürütmesini sağlayacak bir yol bulamadım.\
Ancak, çoğu insan **Hombrew** kullanarak python'u yükler, bu da python'u varsayılan yönetici kullanıcı için **yazılabilir bir konuma** yükler. Bunu şöyle ele geçirebilirsiniz:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
## Tespit

### Kalkan

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)), **enjeksiyon işlemlerini tespit edebilen ve engelleyebilen** açık kaynaklı bir uygulamadır:

- **Çevresel Değişkenler Kullanarak**: Aşağıdaki çevresel değişkenlerin varlığını izleyecektir: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** ve **`ELECTRON_RUN_AS_NODE`**
- **`task_for_pid`** çağrıları Kullanarak: Bir işlemin başka bir işlemin **görev bağlantı noktasını almak istediğinde** (bu, işleme kod enjekte etmeyi sağlar) bulunur.
- **Electron uygulama parametreleri**: Birisi bir Electron uygulamasını hata ayıklama modunda başlatmak ve böylece kod enjekte etmek için **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** komut satırı argümanlarını kullanabilir.
- **Sembolik bağlantılar** veya **sabit bağlantılar** Kullanarak: Genellikle en yaygın kötüye kullanım, **kullanıcı ayrıcalıklarımızla bir bağlantı oluşturmak** ve **daha yüksek ayrıcalıklı bir konuma işaret etmektir**. Hem sabit bağlantılar hem de sembolik bağlantılar için tespit çok basittir. Bağlantıyı oluşturan işlem hedef dosyadan **farklı bir ayrıcalık seviyesine** sahipse, bir **uyarı** oluştururuz. Ne yazık ki sembolik bağlantılar durumunda engelleme mümkün değildir, çünkü bağlantının oluşturulmasından önce bağlantının hedefi hakkında bilgiye sahip değiliz. Bu, Apple'ın EndpointSecuriy çerçevesinin bir kısıtlamasıdır.

### Diğer işlemler tarafından yapılan çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) işlemlerin bir işleme kod enjekte ettiği bilgisi hakkında bilgi almak için **`task_name_for_pid`** işlevini nasıl kullanabileceğinizi bulabilirsiniz ve ardından o diğer işlem hakkında bilgi alabilirsiniz.

Bu işlevi çağırmak için işlemi çalıştıran kişiyle **aynı uid** olmanız veya **root** olmanız gerekir (ve bu işlem, kod enjekte etme yöntemi değil, işlem hakkında bilgi döndürür).

## Referanslar

- [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
- [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
