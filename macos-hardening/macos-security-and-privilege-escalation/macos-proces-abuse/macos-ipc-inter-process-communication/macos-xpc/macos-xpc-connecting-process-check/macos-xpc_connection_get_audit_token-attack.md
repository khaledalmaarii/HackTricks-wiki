# macOS xpc\_connection\_get\_audit\_token Saldırısı

<details>

<summary><strong>AWS hacklemeyi sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar göndererek paylaşın.

</details>

**Daha fazla bilgi için orijinal yazıya bakın:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Bu bir özet:

## Mach Mesajları Temel Bilgileri

Mach Mesajlarının ne olduğunu bilmiyorsanız, bu sayfayı kontrol etmeye başlayın:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Şu anda hatırlamanız gereken şey ([buradan tanım](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

Mach mesajları, mach çekirdeğine yerleştirilmiş **tek alıcı, çok gönderen iletişim** kanalı olan bir _mach portu_ üzerinden gönderilir. **Birden fazla işlem**, bir mach porta mesaj gönderebilir, ancak herhangi bir anda **yalnızca bir işlem** onu okuyabilir. Dosya tanımlayıcıları ve soketler gibi, mach portları çekirdek tarafından tahsis edilir ve yönetilir ve işlemler yalnızca bir tamsayı görür, bu tamsayıyı kullanarak hangi mach portlarının kullanılacağını çekirdeğe belirtebilirler.

## XPC Bağlantısı

Bir XPC bağlantısının nasıl kurulduğunu bilmiyorsanız kontrol edin:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Zafiyet Özeti

Bilmeniz gereken ilginç şey şudur ki **XPC'nin soyutlaması birbirine bağlı bir bağlantıdır**, ancak **çoklu göndericiye sahip olabilen bir teknolojiye dayanır, bu nedenle:**

* Mach portları tek alıcı, **çoklu gönderici**dir.
* Bir XPC bağlantısının denetim belgesi, **en son alınan mesajdan kopyalanır**.
* Bir XPC bağlantısının **denetim belgesini elde etmek**, birçok **güvenlik denetimleri** için kritiktir.

Önceki durum umut verici görünse de, bu duruma neden olmayacak bazı senaryolar vardır ([buradan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Denetim belgeleri genellikle bir bağlantıyı kabul edip etmeyeceğine karar vermek için bir yetkilendirme denetimi için kullanılır. Bu, bir hizmet bağlantısına bir mesaj kullanılarak gerçekleştiğinden, henüz **bağlantı kurulmamıştır**. Bu bağlantı noktasındaki daha fazla mesajlar sadece ek bağlantı istekleri olarak ele alınır. Bu nedenle, **bağlantıyı kabul etmeden önce yapılan denetimler savunmasız değildir** (bu ayrıca `-listener:shouldAcceptNewConnection:` içinde denetim belgesinin güvenli olduğu anlamına gelir). Bu nedenle **belirli eylemleri doğrulayan XPC bağlantıları arıyoruz**.
* XPC olay işleyicileri eşzamanlı olarak işlenir. Bu, bir mesaj için olay işleyicisinin bir sonraki mesaj için çağrılması gerektiği anlamına gelir, hatta eşzamanlı dağıtım kuyruklarında bile. Bu nedenle **XPC olay işleyicisi içinde denetim belgesi başka normal (yanıt dışı!) mesajlar tarafından üzerine yazılamaz**.

Bu, nasıl sömürülebileceğine dair iki farklı yöntem vardır:

1. Varyant1:
* **Sömürü**, hizmet **A** ve hizmet **B'ye** bağlanır.
* Hizmet **B**, kullanıcının yapamayacağı bir **aşamalı işlevi** hizmet **A'da** çağırabilir.
* **Hizmet A**, bir **`dispatch_async`** içinde olmadan **`xpc_connection_get_audit_token`** çağırırken **denetim belgesini alır**.
* Bu nedenle **farklı** bir mesaj, olay işleyicisi dışında asenkron olarak gönderildiği için **Denetim Belgesi üzerine yazılabilir**.
* Sömürü, **hizmet A'ya SEND hakkını hizmet B'ye geçirir**.
* Bu nedenle svc **B**, aslında mesajları hizmet **A'ya gönderir**.
* **Sömürü**, **aşamalı işlemi çağırmaya çalışır**. Bir RC svc **A**, bu **eylemin yetkilendirmesini kontrol ederken svc B Denetim belgesini üzerine yazdı** (sömürünün ayrıcalıklı eylemi çağırma erişimine sahip olmasını sağlar).
2. Varyant 2:
* Hizmet **B**, kullanıcının yapamayacağı bir **aşamalı işlevi** hizmet **A'da** çağırabilir.
* Sömürü, **hizmet A'ya** bağlanır ve hizmetten belirli bir **yanıt bekleyen bir mesaj** gönderir.
* Sömürü, **hizmet** B'ye **o yanıt portunu** geçen bir mesaj gönderir.
* Hizmet **B yanıt verdiğinde**, **mesajı hizmet A'ya gönderirken**, **sömürü** ayrı bir **mesajı hizmet A'ya göndererek ayrıcalıklı bir işlevi** ulaşmaya çalışır ve hizmet B'den gelen yanıtın Denetim belgesini mükemmel anında üzerine yazmasını bekler (Yarış Koşulu).

## Varyant 1: xpc\_connection\_get\_audit\_token'ın olay işleyicisi dışında çağrılması <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Senaryo:

* Bağlanabileceğimiz iki mach hizmeti **`A`** ve **`B`** (kum havuzu profili ve bağlantıyı kabul etmeden önce yetkilendirme denetimlerine dayalı).
* _**A**_, **`B`**'nin geçebileceği belirli bir eylem için bir **yetkilendirme denetimi** yapmalı (ancak uygulamamız yapamaz).
* Örneğin, B bazı **ayrıcalıklara** sahipse veya **root** olarak çalışıyorsa, A'dan ayrıcalıklı bir eylem gerçekleştirmesini istemesine izin verebilir.
* Bu yetkilendirme denetimi için **`A`**, örneğin `dispatch_async`'den **`xpc_connection_get_audit_token`** çağırarak denetim belgesini asenkron olarak alır.

{% hint style="danger" %}
Bu durumda bir saldırgan, **A'dan bir eylem gerçekleştirmesini isteyen bir sömürü** oluşturabilirken **B'nin A'ya mesaj göndermesini sağlayan bir Yarış Koşulu** tetikleyebilir. RC başarılı olduğunda, **B'nin denetim belgesi**, **sömürü**nün A tarafından **işlenirken** hafızaya kopyalanır ve **sömürü**nün **yalnızca B'nin isteyebileceği ayrıcalıklı eyleme erişimini** verir.
{% endhint %}

Bu, **`A`** olarak `smd` ve **`B`** olarak `diagnosticd` ile gerçekleşti. smb'den [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) işlevi, yeni bir ayrıcalıklı yardımcı aracı (root olarak) yüklemek için kullanılabilir. **Root** olarak çalışan bir işlem **smd'ye** ulaşırsa, başka hiçbir denetim yapılmaz.

Bu nedenle hizmet **B**, **root** olarak çalıştığından ve bir işlemi **izlemek** için kullanılabileceğinden, izleme başladığında saniyede **çoklu mesaj gönderecektir.**

Saldırıyı gerçekleştirmek için:

1. Standart XPC protokolünü kullanarak `smd` adlı hizmete bir **bağlantı** başlatın.
2. `diagnosticd`'ye ikincil bir **bağlantı** oluşturun. Normal prosedürün aksine, iki yeni mach port oluşturmak ve göndermek yerine, istemci portu gönderme hakkı, `smd` bağlantısıyla ilişkilendirilen **gönderme hakkının bir kopyası ile değiştirilir**.
3. Sonuç olarak, XPC mesajları `diagnosticd`'ye gönderilebilir, ancak `diagnosticd`'den gelen yanıtlar `smd`'ye yönlendirilir. `smd` için, hem kullanıcıdan hem de `diagnosticd`'den gelen mesajların aynı bağlantıdan geldiği görünmektedir.

![Sömürü sürecini tasvir eden resim](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)
4. Sonraki adım, `diagnosticd`'ye seçilen bir süreci (muhtemelen kullanıcının kendi sürecini) izlemesini talimatlandırmayı içerir. Aynı anda, rutin 1004 mesajlarının bir seli `smd`'ye gönderilir. Buradaki amaç, ayrıcalıklı izinlerle bir araç yüklemektir.
5. Bu eylem, `handle_bless` işlevi içinde bir yarış koşulunu tetikler. Zamanlama kritiktir: `xpc_connection_get_pid` işlevi çağrısının kullanıcının sürecinin PID'sini döndürmesi gerekir (çünkü ayrıcalıklı araç kullanıcının uygulama paketinde bulunur). Ancak, `xpc_connection_get_audit_token` işlevi, özellikle `connection_is_authorized` alt rutini içinde, `diagnosticd`'ye ait olan denetim belgesine başvurmalıdır.

## Varyant 2: yanıt yönlendirme

Bir XPC (Çapraz Süreç İletişimi) ortamında, olay işleyicileri eşzamanlı olarak yürütülmezken, yanıt mesajlarının işlenmesi benzersiz bir davranışa sahiptir. Özellikle, yanıt bekleyen mesajların gönderilmesi için iki farklı yöntem bulunmaktadır:

1. **`xpc_connection_send_message_with_reply`**: Burada, XPC mesajı belirlenmiş bir sıra üzerinde alınır ve işlenir.
2. **`xpc_connection_send_message_with_reply_sync`**: Buna karşılık, bu yöntemde XPC mesajı mevcut dağıtım sırasında alınır ve işlenir.

Bu ayrım, **yanıt paketlerinin XPC olay işleyicisinin yürütülmesiyle eşzamanlı olarak ayrıştırılmasına olanak tanır**. Özellikle, `_xpc_connection_set_creds`, denetim belgesinin kısmi üzerine yazılmasına karşı koruma sağlamak için kilit mekanizması uygular, ancak bu korumayı tüm bağlantı nesnesine genişletmez. Sonuç olarak, bir paketin ayrıştırılması ve olay işleyicisinin yürütülmesi arasındaki aralıkta denetim belgesinin değiştirilebileceği bir zafiyet oluşturur.

Bu zafiyeti sömürmek için aşağıdaki kurulum gereklidir:

* İki mach hizmeti, **`A`** ve **`B`** olarak adlandırılan, her ikisi de bir bağlantı kurabilir.
* Hizmet **`A`**, yalnızca **`B`**'nin gerçekleştirebileceği belirli bir eylem için bir yetkilendirme kontrolü içermelidir (kullanıcının uygulaması yapamaz).
* Hizmet **`A`**, yanıt bekleyen bir mesaj göndermelidir.
* Kullanıcı, yanıt vereceği **`B`**'ye bir mesaj gönderebilir.

Sömürü süreci aşağıdaki adımları içerir:

1. Hizmet **`A`**'nın yanıt bekleyen bir mesaj göndermesini bekleyin.
2. Yanıtı doğrudan **`A`**'ya yanıtlamak yerine, yanıt bağlantı noktası ele geçirilir ve **`B`**'ye bir mesaj göndermek için kullanılır.
3. Ardından, yasaklanan eylemi içeren bir mesaj gönderilir ve bu mesajın, **`B`**'den gelen yanıtla eşzamanlı olarak işlenmesi beklenir.

Yukarıda açıklanan saldırı senaryosunun görsel temsili aşağıda verilmiştir:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Keşif Problemleri

* **Örneklerin Bulunmasındaki Zorluklar**: `xpc_connection_get_audit_token` kullanımı örneklerini hem statik hem de dinamik olarak aramak zorlu oldu.
* **Metodoloji**: `xpc_connection_get_audit_token` işlevini kancalamak için Frida kullanıldı, ancak bu yöntem, kancalanan sürece sınırlıydı ve aktif kullanım gerektiriyordu.
* **Analiz Araçları**: IDA/Ghidra gibi araçlar, ulaşılabilir mach hizmetlerini incelemek için kullanıldı, ancak bu süreç, dyld paylaşılan önbelleği içeren çağrılar tarafından karmaşık hale getirildi ve zaman alıcıydı.
* **Betik Sınırlamaları**: `dispatch_async` bloklarından `xpc_connection_get_audit_token` çağrılarını analiz etmek için betik oluşturma girişimleri, blokların ayrıştırılmasındaki karmaşıklıklar ve dyld paylaşılan önbelleği ile etkileşimler nedeniyle engellendi.

## Düzeltme <a href="#the-fix" id="the-fix"></a>

* **Bildirilen Sorunlar**: `smd` içinde bulunan genel ve özel sorunları detaylandıran bir rapor Apple'a sunuldu.
* **Apple'ın Yanıtı**: Apple, `smd` içindeki sorunu `xpc_connection_get_audit_token`'ı `xpc_dictionary_get_audit_token` ile değiştirerek ele aldı.
* **Düzeltmenin Doğası**: `xpc_dictionary_get_audit_token` işlevi, denetim belgesini doğrudan alır ve alınan XPC mesajına bağlı mach mesajından denetim belgesini alır. Bununla birlikte, `xpc_connection_get_audit_token` gibi genel API'nın bir parçası değildir.
* **Daha Kapsamlı Bir Düzeltmenin Eksikliği**: Neden Apple'ın bağlantının kaydedilen denetim belgesiyle uyuşmayan mesajları reddetmek gibi daha kapsamlı bir düzeltme uygulamadığı belirsizdir. Bazı senaryolarda (örneğin, `setuid` kullanımı) meşru denetim belgesi değişikliklerinin olasılığı bir faktör olabilir.
* **Mevcut Durum**: Sorun, iOS 17 ve macOS 14'te devam etmekte olup, bunu tanımlamak ve anlamak isteyenler için bir zorluk oluşturmaktadır.
