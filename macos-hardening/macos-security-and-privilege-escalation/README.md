# macOS Güvenliği ve Ayrıcalık Yükseltme

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin</summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* **Deneyimli hackerlar ve ödül avcılarıyla iletişim kurmak için** [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanını ve zorluklarını ele alan içeriklerle etkileşime geçin

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni ödül avları ve önemli platform güncellemeleri hakkında bilgi edinin

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliği yapmaya başlayın!

## Temel MacOS

MacOS hakkında bilgi sahibi değilseniz, MacOS'un temellerini öğrenmeye başlamalısınız:

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

* **Çekirdek**nin **mimari**si

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Ortak macOS **ağ hizmetleri ve protokolleri**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Açık kaynaklı** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Bir `tar.gz` indirmek için, [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) gibi bir URL'yi [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) şeklinde değiştirin

### MacOS MDM

Şirketlerde **macOS** sistemleri genellikle bir MDM ile yönetilir. Bu nedenle, bir saldırganın **bunun nasıl çalıştığını** bilmesi ilginç olabilir:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - İnceleme, Hata Ayıklama ve Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Güvenlik Korumaları

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Saldırı Yüzeyi

### Dosya İzinleri

Eğer **root olarak çalışan bir işlem**, bir kullanıcının kontrol edebileceği bir dosyaya yazarsa, kullanıcı bu durumu **ayrıcalıkları yükseltmek** için kullanabilir.\
Bu durumlar aşağıdaki durumlarda meydana gelebilir:

* Kullanıcı tarafından zaten oluşturulmuş olan dosya (kullanıcıya ait)
* Kullanıcıya bir grup tarafından yazılabilir hale getirilen dosya
* Kullanıcının sahip olduğu bir dizin içinde kullanılan dosya (kullanıcı dosyayı oluşturabilir)
* Kullanıcının yazma erişimine sahip olduğu bir dizin içinde yer alan dosya (kullanıcı dosyayı oluşturabilir)

**Root tarafından kullanılacak bir dosya** oluşturabilmek, bir kullanıcının içeriğinden **yararlanmasına** veya hatta onu başka bir yere yönlendirmek için **sembolik bağlantılar/sabit bağlantılar** oluşturmasına olanak tanır.

Bu tür zafiyetler için **savunmasız `.pkg` yükleyicilerini** kontrol etmeyi unutmayın:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### Dosya Uzantısı ve URL şeması uygulama yöneticileri

Dosya uzantıları tarafından kaydedilen garip uygulamalar kötüye kullanılabilir ve farklı uygulamalar belirli protokolleri açmak için kaydedilebilir

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Ayrıcalık Yükseltme

MacOS'ta **uygulamaların ve ikili dosyaların** diğerlerinden daha ayrıcalıklı olmalarını sağlayan klasörlere veya ayarlara erişim izinleri olabilir.

Bu nedenle, bir macOS makinesini başarılı bir şekilde ele geçirmek isteyen bir saldırganın, TCC ayrıcalıklarını **yükseltmesi** (veya ihtiyacına bağlı olarak **SIP'yi atlaması**) gerekecektir.

Bu ayrıcalıklar genellikle uygulamanın imzalandığı **yetkilendirmeler** veya uygulamanın bazı erişimleri talep etmesi ve **kullanıcının bunları onayladıktan sonra** TCC veritabanlarında bulunabilmesi şeklinde verilir. Bir işlem, bu ayrıcalıkları genellikle **miras** aldığı için, bu ayrıcalıklara sahip bir sürecin **çocuğu** olarak bu ayrıcalıkları elde edebilir.

Aşağıdaki bağlantıları takip ederek [**TCC'de ayrıcalıkları yükseltmek**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**TCC'yi atlamak**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) ve geçmişte [**SIP'in nasıl atlatıldığı**](macos-security-protections/macos-sip.md#sip-bypasses) hakkında farklı yöntemlere ulaşabilirsiniz.

## macOS Geleneksel Ayrıcalık Yükseltme

Tabii ki, bir kırmızı takımın perspektifinden root ayrıcalıklarına yükseltme konusunda da ilgilenmelisiniz. İpuçları için aşağıdaki gönderiyi kontrol edin:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Referanslar

* [**OS X Olay Yanıtı: Betikleme ve Analiz**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve ödül avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanına ve zorluklarına dalmış içeriklerle etkileşim kurun

**Gerçek Zamanlı Hack Haberleri**\
Hızlı tempolu hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin

**En Son Duyurular**\
Yeni ödül avları başlatma ve önemli platform güncellemeleri hakkında bilgi edinin

**Bize** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **katılın ve bugün en iyi hackerlarla işbirliği yapmaya başlayın!**

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
