# Diğer Web Hileleri

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı takip edin**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

### Host başlığı

Birçok kez, arka uç, bazı işlemleri gerçekleştirmek için **Host başlığına güvenir**. Örneğin, şifre sıfırlama e-postası göndermek için değerini **alan olarak kullanabilir**. Bu nedenle, şifrenizi sıfırlamak için bir bağlantı içeren bir e-posta aldığınızda, kullanılan alan Host başlığına koyduğunuz alandır. Ardından, diğer kullanıcıların şifre sıfırlama kodlarını çalmak için kullanıcıların şifre sıfırlama isteğini isteyebilir ve alanı kendi kontrolünüzde olan bir alanla değiştirebilirsiniz. [Yazı](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Kullanıcının sıfırlama bağlantısına tıklamasını beklemenize bile gerek olmadığını unutmayın, çünkü muhtemelen **spam filtreleri veya diğer aracı cihazlar/botlar** bunu analiz etmek için tıklayabilir.
{% endhint %}

### Oturum booleanları

Bazen bazı doğrulamaları doğru bir şekilde tamamladığınızda, arka uç, oturumunuzdaki bir güvenlik özelliğine "True" değeriyle bir boolean ekler. Ardından, farklı bir uç nokta, bu kontrolü başarıyla geçip geçmediğinizi bilecektir.\
Ancak, kontrolü **geçerseniz** ve oturumunuzun güvenlik özelliğinde "True" değeri verilirse, **erişim izniniz olmamasına rağmen** aynı özelliğe bağlı **diğer kaynaklara erişmeyi deneyebilirsiniz**. [Yazı](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Kayıt işlevi

Var olan bir kullanıcı olarak kaydolmayı deneyin. Ayrıca noktalar, çok fazla boşluk ve Unicode gibi eşdeğer karakterleri kullanmayı da deneyin.

### E-postaları ele geçirme

Bir e-posta kaydedin, onaylamadan önce e-postayı değiştirin, ardından yeni onay e-postası ilk kaydedilen e-postaya gönderilirse, herhangi bir e-postayı ele geçirebilirsiniz. Veya ikinci e-postayı ilkini onaylayarak etkinleştirebilirseniz, herhangi bir hesabı ele geçirebilirsiniz.

### Şirketlerin dahili servis masasına erişim (atlassian kullanarak)

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE yöntemi

Geliştiriciler, üretim ortamında çeşitli hata ayıklama seçeneklerini devre dışı bırakmayı unutabilirler. Örneğin, HTTP `TRACE` yöntemi teşhis amaçlı tasarlanmıştır. Etkinleştirildiğinde, web sunucusu, `TRACE` yöntemini kullanan isteklere yanıt olarak aldığı tam isteği yanıtta yankılar. Bu davranış genellikle zararsızdır, ancak bazen, ters proxy'ler tarafından isteklere eklenen dahili kimlik doğrulama başlıklarının adı gibi bilgilerin ifşa edilmesine yol açar.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı takip edin**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
