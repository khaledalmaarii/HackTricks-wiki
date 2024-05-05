# macOS Güvenliği ve Yetki Yükseltme

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Bize katılın** 💬 [**Discord grubunda**](https://discord.gg/hRep4RUj7f) veya [**telegram grubunda**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanına ve zorluklarına inen içeriklerle etkileşime girin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Başlatılan en yeni ödül avı programları ve önemli platform güncellemeleri hakkında bilgi sahibi olun

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliğine başlayın!

## Temel MacOS

Eğer macOS hakkında bilgi sahibi değilseniz, macOS'ın temellerini öğrenmeye başlamalısınız:

* Özel macOS **dosyaları ve izinleri:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Ortak macOS **kullanıcıları**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Çekirdeğin** yapısı

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Ortak macOS ağ hizmetleri ve protokolleri

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Açık kaynak** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Bir `tar.gz` dosyası indirmek için [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) gibi bir URL'yi [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) şeklinde değiştirin

### MacOS MDM

Şirketlerde **macOS** sistemleri büyük olasılıkla bir MDM ile **yönetilecektir**. Bu nedenle, bir saldırganın bakış açısından **bu nasıl çalışır** öğrenmek ilginç olacaktır:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - İnceleme, Hata Ayıklama ve Fazlama

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Güvenlik Korumaları

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Saldırı Yüzeyi

### Dosya İzinleri

Eğer **kök olarak çalışan bir işlem** bir kullanıcı tarafından kontrol edilebilen bir dosyaya yazarsa, kullanıcı bu durumu **yetki yükseltmek** için kötüye kullanabilir.\
Bu durumlar şunlardan kaynaklanabilir:

* Kullanıcı tarafından zaten oluşturulmuş olan dosya (kullanıcı tarafından sahip olunan)
* Dosya, bir grup tarafından yazılabilir durumdaysa kullanıcı tarafından yazılabilir
* Dosya, kullanıcı tarafından sahip olunan bir dizinin içinde ise (kullanıcı dosyayı oluşturabilir)
* Dosya, kök tarafından sahip olunan bir dizinin içinde ise ancak kullanıcının bir grup sayesinde yazma erişimi varsa (kullanıcı dosyayı oluşturabilir)

**Kök tarafından kullanılacak bir dosya oluşturabilmek**, bir kullanıcının içeriğinden **yararlanmasına** veya hatta onu başka bir yere **sembolik bağlantılar/sabit bağlantılar** oluşturmasına olanak tanır.

Bu tür zafiyetler için **savunmasız `.pkg` yükleyicilerini** kontrol etmeyi unutmayın:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Dosya Uzantısı ve URL şema uygulama yönlendiricileri

Dosya uzantıları tarafından kaydedilen garip uygulamalar kötüye kullanılabilir ve farklı uygulamalar belirli protokolleri açmak için kaydedilebilir

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Yetki Yükseltme

macOS'ta **uygulamalar ve ikili dosyalar**, diğerlerinden daha ayrıcalıklı hale getiren klasörleri veya ayarları erişmek için izinlere sahip olabilir.

Bu nedenle, bir macOS makinesini başarılı bir şekilde ele geçirmek isteyen bir saldırganın **TCC ayrıcalıklarını yükseltmesi** gerekecektir (veya ihtiyaçlarına bağlı olarak **SIP'yi atlaması** gerekebilir).

Bu ayrıcalıklar genellikle uygulamanın imzalandığı **yetkilendirmeler** şeklinde verilir veya uygulama bazı erişimler isteyebilir ve **kullanıcı bunları onayladıktan sonra** bu erişimler **TCC veritabanlarında** bulunabilir. Bir işlemin bu ayrıcalıkları elde etmenin başka bir yolu da, genellikle **miras alındıkları için** bu ayrıcalıklara sahip bir işlemin **çocuğu olmaktır**.

Bu bağlantıları takip ederek farklı yolları bulabilirsiniz: [**TCC'de ayrıcalıkları yükseltmek**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**TCC'yi atlamak**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) ve geçmişte **SIP'nin nasıl atlatıldığını** görmek için [**buraya**](macos-security-protections/macos-sip.md#sip-bypasses) bakın.

## macOS Geleneksel Yetki Yükseltme

Tabii ki, bir kırmızı takımın bakış açısından kök yetkilerine yükselmeniz de önemli olacaktır. Bazı ipuçları için aşağıdaki yazıya göz atın:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Referanslar

* [**OS X Olay Yanıtı: Betikleme ve Analiz**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın ve deneyimli hackerlar ve ödül avcıları ile iletişim kurun!

**Hacking İçgörüleri**\
Hacking'in heyecanını ve zorluklarını inceleyen içeriklerle etkileşime geçin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yayınlanan en yeni ödül avı programları ve önemli platform güncellemeleri hakkında bilgi edinin

**Bize Katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliğine başlayın!

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
