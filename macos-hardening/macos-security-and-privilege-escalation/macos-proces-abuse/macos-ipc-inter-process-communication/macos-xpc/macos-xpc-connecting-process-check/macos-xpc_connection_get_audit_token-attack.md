# macOS xpc\_connection\_get\_audit\_token Saldırısı

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

**Daha fazla bilgi için orijinal yazıyı kontrol edin: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. İşte bir özet:


## Mach Mesajları Temel Bilgileri

Mach Mesajları hakkında bilgi sahibi değilseniz, bu sayfayı kontrol etmeye başlayın:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Şimdilik hatırlamanız gereken şey ([buradan tanım](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach mesajları, mach çekirdeğine yerleştirilmiş **tek alıcı, çok gönderici iletişim** kanalı olan bir _mach portu_ üzerinden gönderilir. **Birden fazla işlem**, bir mach portuna mesaj gönderebilir, ancak herhangi bir noktada **yalnızca bir işlem ondan okuyabilir**. Dosya tanımlayıcıları ve soketler gibi, mach portları çekirdek tarafından tahsis edilir ve yönetilir ve işlemler yalnızca bir tamsayı görür, bu tamsayıyı kullanarak hangi mach portlarını kullanmak istediklerini çekirdeğe bildirebilirler.

## XPC Bağlantısı

XPC bağlantısının nasıl kurulduğunu bilmiyorsanız kontrol edin:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Zafiyet Özeti

Bilmeniz gereken ilginç olan şey, **XPC'nin soyutlamasının bir bir-bir bağlantı** olduğu, ancak **çoklu göndericiye sahip olabilen bir teknoloji üzerine kurulu olduğudur:**

* Mach portları tek alıcı, **çoklu gönderici**dir.
* Bir XPC bağlantısının denetim belgesi, **en son alınan mesajdan kopyalanan denetim belgesidir**.
* Bir XPC bağlantısının denetim belgesini elde etmek, birçok **güvenlik kontrolü** için önemlidir.

Önceki durum umut verici görünse de, bazı senaryolarda bu sorunlara neden olmayacağı ([buradan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Denetim belgeleri, bir bağlantıyı kabul etmek için yetkilendirme kontrolü yapmak için sıklıkla kullanılır. Bu, hizmet bağlantısına bir mesaj kullanılarak gerçekleştiğinden, **henüz bir bağlantı kurulmamıştır**. Bu bağlantı noktasındaki daha fazla mesajlar yalnızca ek bağlantı istekleri olarak ele alınır. Bu nedenle, **bir bağlantıyı kabul etmeden önce yapılan kontrol**lere karşı savunmasız değildir (bu aynı zamanda `-listener:shouldAcceptNewConnection:` içinde denetim belgesinin güvende olduğu anlamına gelir). Bu nedenle, belirli eylemleri doğrulayan XPC bağlantılarını arıyoruz.
* XPC olay işleyicileri eşzamanlı olarak işlenir. Bu, bir mesaj için olay işleyicisinin bir sonraki mesaj için çağrılmadan tamamlanması gerektiği anlamına gelir, hatta eşzamanlı dağıtım kuyruklarında bile. Bu nedenle, bir **XPC olay işleyicisi içinde denetim belgesi başka normal (yanıt olmayan!) mesajlar tarafından üzerine yazılamaz**.

Bu, sömürülebilecek iki farklı yöntemdir:

1. Varyant 1:
* **Sömürü**, hizmet **A** ve hizmet **B'ye** bağlanır.
* Hizmet **B**, kullanıcının yapamayacağı bir **yetkili işlevi** hizmet **A**'da çağırabilir.
* Hizmet **A**, **`dispatch_async`** içinde olmadığı sürece **`xpc_connection_get_audit_token`**'ı çağırırken.
* Bu nedenle, **farklı bir mesaj denetim belgesini üzerine yazabilir**, çünkü olay işleyicisi dışında asenkron olarak gönderiliyor.
* Sömürü, **hizmet A'ya SEND hakkını hizmet B'ye** geçirir.
* Bu nedenle, svc **B**, mesajları hizmet **A'ya gönderir**.
* Sömürü, **yetkili eylemi çağırmaya çalışır**. Bir RC svc **A**, bu **eylemin yetkilendirmesini kontrol ederken**, svc B denetim belgesini üzerine yazdı (sömürüye yetkili eylemi çağırma erişimi sağlar).
2. Varyant 2:
* Hizmet **B**, kullanıcının yapamayacağı bir **yetkili işlevi** hizmet **A**'da çağırabilir.
* Sömürü, **hizmet A'ya** bağlanır ve belirli bir **yanıt bekleyen bir mesajı** sömürüye **gönderir**.
* Sömürü, **hizmet B'ye** sömürüye **yanıt bekleyen o yanıt bağlantısını** geçiren bir mesaj gönderir.
* Hizmet **B yanıt verdiğinde**, **mesajı hizmet A'ya gönderir**, **sömürü** ise **hizmet A'ya** farklı bir **mesaj gönderir** ve aynı zamanda hizmet B'den gelen yanıt
4. Bir sonraki adım, `diagnosticd`'ye belirli bir süreci (potansiyel olarak kullanıcının kendi sürecini) izlemesi talimatını vermekle ilgilidir. Aynı anda, `smd`'ye rutin 1004 mesajlarının bir seli gönderilir. Buradaki amaç, ayrıcalıklı yetkilere sahip bir araç yüklemektir.
5. Bu eylem, `handle_bless` işlevi içinde bir yarış durumu tetikler. Zamanlama önemlidir: `xpc_connection_get_pid` işlevi çağrısı, kullanıcının sürecinin PID'sini döndürmelidir (ayrıcalıklı araç kullanıcının uygulama paketinde bulunduğu için). Bununla birlikte, `xpc_connection_get_audit_token` işlevi, özellikle `connection_is_authorized` alt rutini içinde, `diagnosticd`'ye ait denetim belirtecinin başvuruda bulunmalıdır.

## Varyant 2: yanıt yönlendirme

Bir XPC (Çapraz Süreç İletişimi) ortamında, olay işleyicileri eşzamanlı olarak çalışmasa da, yanıt mesajlarının işlenmesi benzersiz bir davranışa sahiptir. Özellikle, yanıt bekleyen mesajları göndermek için iki ayrı yöntem bulunmaktadır:

1. **`xpc_connection_send_message_with_reply`**: Burada, XPC mesajı belirli bir sıra üzerinde alınır ve işlenir.
2. **`xpc_connection_send_message_with_reply_sync`**: Bunun aksine, bu yöntemde, XPC mesajı mevcut dağıtım sırasında alınır ve işlenir.

Bu ayrım, **yanıt paketlerinin bir XPC olay işleyicisinin yürütülmesiyle eşzamanlı olarak ayrıştırılabilme** olasılığına izin verdiği için önemlidir. Özellikle, `_xpc_connection_set_creds`, denetim beltecinin kısmi üzerine yazılmasına karşı koruma sağlamak için kilit mekanizması uygular, ancak bu korumayı tüm bağlantı nesnesine genişletmez. Sonuç olarak, bir paketin ayrıştırılması ve olay işleyicisinin yürütülmesi arasındaki süre zarfında denetim belteci değiştirilebilme zafiyeti oluşur.

Bu zafiyeti sömürmek için aşağıdaki kurulum gereklidir:

- İki mach hizmeti, **`A`** ve **`B`** olarak adlandırılan, her ikisi de bir bağlantı kurabilir.
- **`A`** hizmeti, yalnızca **`B`**'nin gerçekleştirebileceği belirli bir eylem için bir yetkilendirme kontrolü içermelidir (kullanıcının uygulaması yapamaz).
- **`A`** hizmeti, bir yanıt bekleyen bir mesaj göndermelidir.
- Kullanıcı, **`B`**'ye yanıt vereceği bir mesaj gönderebilir.

Sömürü süreci aşağıdaki adımları içerir:

1. **`A`** hizmetinin, yanıt bekleyen bir mesaj göndermesini bekleyin.
2. Yanıtı doğrudan **`A`**'ya yanıtlamak yerine, yanıt bağlantı noktası ele geçirilir ve **`B`** hizmetine bir mesaj göndermek için kullanılır.
3. Ardından, yasaklanan eylemi içeren bir mesaj gönderilir ve bu mesajın **`B`**'den gelen yanıtla eşzamanlı olarak işlenmesi beklenir.

Aşağıda, açıklanan saldırı senaryosunun görsel bir temsili bulunmaktadır:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)


<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Keşif Sorunları

- **Örneklerin Bulunmasındaki Zorluklar**: `xpc_connection_get_audit_token` kullanımının hem statik hem de dinamik olarak bulunması zorlu bir süreçti.
- **Yöntemoloji**: `xpc_connection_get_audit_token` işlevini kancalamak için Frida kullanıldı, ancak olay işleyicilerinden kaynaklanmayan çağrıları filtrelemek gerekiyordu. Ancak bu yöntem, kancalanan süreçle sınırlıydı ve etkin kullanım gerektiriyordu.
- **Analiz Araçları**: Erişilebilir mach hizmetlerini incelemek için IDA/Ghidra gibi araçlar kullanıldı, ancak dyld paylaşılan önbelleğiyle ilgili çağrılar tarafından karmaşıklaştırılan ve zaman alıcı bir süreçti.
- **Betikleme Sınırlamaları**: `dispatch_async` bloklarından `xpc_connection_get_audit_token` çağrılarının analizini betiklemeye yönelik girişimler, blokların ayrıştırılması ve dyld paylaşılan önbelleğiyle etkileşim gibi karmaşıklıklar nedeniyle engellendi.

## Düzeltme <a href="#the-fix" id="the-fix"></a>

- **Bildirilen Sorunlar**: `smd` içinde bulunan genel ve özel sorunları detaylandıran bir rapor Apple'a gönderildi.
- **Apple'ın Yanıtı**: Apple, `smd` içindeki sorunu, `xpc_connection_get_audit_token` işlevini `xpc_dictionary_get_audit_token` ile değiştirerek çözdü.
- **Düzeltmenin Niteliği**: `xpc_dictionary_get_audit_token` işlevi, alınan XPC mesajına bağlı olan mach mesajından denetim beltecinin doğrudan alınmasını sağladığı için güvenli kabul edilir. Bununla birlikte, `xpc_connection_get_audit_token` gibi, bu işlev de genel API'nin bir parçası değildir.
- **Daha Kapsamlı Bir Düzeltmenin Eksikliği**: Apple'ın, bağlantının kaydedilen denetim belteciyle uyumlu olmayan mesajları atma gibi daha kapsamlı bir düzeltme uygulamaması belirsizdir. Belirli senaryolarda (örneğin, `setuid` kullanımı) meşru denetim belteci değişikliklerinin olasılığı bir faktör olabilir.
- **Mevcut Durum**: Sorun, iOS 17 ve macOS 14'te hala devam etmektedir ve tanımlanması ve anlaşılması için çaba sarf edenler için bir zorluk oluşturmaktadır.
