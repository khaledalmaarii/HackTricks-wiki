# macOS Güvenliği ve Yetki Yükseltme

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanına ve zorluklarına inen içeriklerle etkileşime girin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni ödül avı başlatmaları ve önemli platform güncellemeleri hakkında bilgilenin

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliğine başlayın!

## Temel MacOS

MacOS'u tanımıyorsanız, MacOS'un temellerini öğrenmeye başlamalısınız:

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

* Ortak macOS **ağ hizmetleri ve protokolleri**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Açık kaynak** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Bir `tar.gz` indirmek için [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) gibi bir URL'yi [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) şeklinde değiştirin

### MacOS MDM

Şirketlerde **macOS** sistemlerinin büyük olasılıkla bir **MDM ile yönetileceği** unutulmamalıdır. Bu nedenle, bir saldırganın bakış açısından **bu nasıl çalışır** bilgisi önemlidir:

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

* Kullanıcı tarafından zaten oluşturulmuş olan dosya (kullanıcıya ait)
* Dosya, bir grup tarafından yazılabilir durumda olduğu için kullanıcı tarafından yazılabilir
* Dosya, kullanıcıya ait olan bir dizin içinde bulunuyorsa (kullanıcı dosyayı oluşturabilir)
* Dosya, kök tarafından sahip olunan bir dizin içinde bulunuyorsa ancak kullanıcının bir grup tarafından yazma erişimi varsa (kullanıcı dosyayı oluşturabilir)

**Kök tarafından kullanılacak bir dosya** oluşturabilmek, bir kullanıcının dosyanın içeriğinden **yararlanmasına** veya hatta onu başka bir yere yönlendirmek için **sembolik bağlar/sabit bağlar** oluşturmasına olanak tanır.

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

MacOS'ta **uygulamalar ve ikili dosyalar**, diğerlerinden daha ayrıcalıklı hale getiren klasörleri veya ayarları erişmek için izinlere sahip olabilir.

Bu nedenle, bir macOS makinesini başarılı bir şekilde ele geçirmek isteyen bir saldırganın, MacOS'ta **TCC ayrıcalıklarını yükseltmesi** gerekecektir (veya ihtiyacına bağlı olarak **SIP'yi atlaması** gerekebilir).

Bu ayrıcalıklar genellikle uygulamanın imzalandığı **yetkilendirme** biçiminde verilir veya uygulama bazı erişimler isteyebilir ve **kullanıcı onayladıktan sonra** bu erişimler **TCC veritabanlarında** bulunabilir. Bir işlemin bu ayrıcalıkları elde etmenin başka bir yolu da, genellikle **miras alındıkları için** bu ayrıcalıklara sahip bir işlemin **çocuğu olmaktır**.

Bu bağlantıları takip ederek [**TCC'de ayrıcalıkları yükseltme**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**TCC'yi atlamak için**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) ve geçmişte **SIP'nin nasıl atlatıldığını** öğrenin.

## macOS Geleneksel Yetki Yükseltme

Tabii ki, bir kırmızı takımın bakış açısından kök yetkilerine yükselmek de önemlidir. Bazı ipuçları için aşağıdaki gönderiyi kontrol edin:

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

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın ve deneyimli hackerlar ve ödül avcıları ile iletişime geçin!

**Hacking İçgörüleri**\
Hacking'in heyecanına ve zorluklarına inen içeriklerle etkileşime girin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasında gerçek zamanlı haberler ve içgörülerle güncel kalın

**En Son Duyurular**\
Yeni ödül avı başlatmaları ve önemli platform güncellemeleri hakkında bilgilenin

**Bize Katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliğine başlayın!

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Destek HackTricks</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
