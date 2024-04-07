# Diğer Web Hileleri

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin**.
* **Hacking hilelerinizi paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

### Ana bilgisayar başlığı

Arka uç bazen bazı işlemleri gerçekleştirmek için **Ana Bilgisayar başlığına güvenir**. Örneğin, şifre sıfırlama bağlantısı göndermek için değerini kullanabilir. Bu nedenle, şifrenizi sıfırlamak için bir bağlantı içeren bir e-posta aldığınızda, kullanılan alan, Ana Bilgisayar başlığına koyduğunuz alandır. Sonra, diğer kullanıcıların şifre sıfırlama isteğinde bulunabilir ve alanı kendi kontrolünüzde olan bir alana değiştirerek şifre sıfırlama kodlarını çalabilirsiniz. [Açıklama](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Kullanıcının sıfırlama bağlantısına tıklamasını beklemenize gerek olmadığını unutmayın, çünkü belki de **spam filtreleri veya diğer aracı cihazlar/botlar** bağlantıyı analiz etmek için tıklar.
{% endhint %}

### Oturum boole'ları

Bazen doğrulamayı doğru bir şekilde tamamladığınızda, arka uç **oturumunuzdaki bir güvenlik özniteliğine "True" değerini ekleyebilir**. Sonra, farklı bir uç nokta, o kontrolü başarıyla geçip geçmediğinizi bilecektir.\
Ancak, eğer **kontrolü geçerseniz** ve oturumunuz güvenlik özniteliğinde "True" değerini alırsa, **aynı özniteliğe bağlı** ancak **erişim izniniz olmaması gereken diğer kaynaklara erişmeyi deneyebilirsiniz**. [Açıklama](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Kayıt işlevselliği

Var olan bir kullanıcı olarak kayıt olmayı deneyin. Noktaları, çok fazla boşluk ve Unicode karakterlerini kullanarak eşdeğer karakterlerle de deneyin.

### E-postaları ele geçirme

Bir e-posta kaydedin, onaylamadan önce e-postayı değiştirin, sonra eğer yeni onay e-postası ilk kayıtlı e-postaya gönderilirse, herhangi bir e-postayı ele geçirebilirsiniz. Ya da ikinci e-postayı etkinleştirebilirseniz, ilkini onaylayarak herhangi bir hesabı ele geçirebilirsiniz.

### Şirketlerin iç servis masasına erişim

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE yöntemi

Geliştiriciler, üretim ortamında çeşitli hata ayıklama seçeneklerini devre dışı bırakmayı unutabilirler. Örneğin, HTTP `TRACE` yöntemi tanısal amaçlar için tasarlanmıştır. Etkinleştirilirse, web sunucusu, `TRACE` yöntemini kullanan isteklere yanıt vererek aldığı tam isteği yanıt olarak yansıtacaktır. Bu davranış genellikle zararsızdır, ancak bazen, ters proxy'ler tarafından isteklere eklenen dahili kimlik doğrulama başlıklarının adını içeren bilgilerin ifşasına yol açabilir.![Gönderi için resim](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Gönderi için resim](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)
