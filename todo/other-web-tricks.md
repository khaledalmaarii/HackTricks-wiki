# Diğer Web Hileleri

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking hilelerini paylaşmak için **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek katkıda bulunun.

</details>
{% endhint %}

### Host başlığı

Arka uç bazen bazı işlemleri gerçekleştirmek için **Host başlığına** güvenir. Örneğin, şifre sıfırlama bağlantısı göndermek için bu değeri kullanabilir. Bu nedenle, şifrenizi sıfırlamak için bir bağlantı içeren bir e-posta aldığınızda, kullanılan alan, Host başlığına koyduğunuz alandır. Sonra, diğer kullanıcıların şifre sıfırlama isteğinde bulunabilir ve alanı kendi kontrolünüzde olan bir alana değiştirerek şifre sıfırlama kodlarını çalabilirsiniz. [Çözüm](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Kullanıcının sıfırlama bağlantısına tıklamasını beklemenize gerek olmadığını unutmamanız önemlidir, çünkü belki de **spam filtreleri veya diğer aracı cihazlar/botlar bunu analiz etmek için tıklar**.
{% endhint %}

### Oturum booleanları

Bazen doğrulamayı doğru bir şekilde tamamladığınızda, arka uç **oturumunuza "True" değerinde bir boolean ekleyebilir**. Sonra, farklı bir uç nokta, o kontrolü başarıyla geçip geçmediğinizi bilecektir.\
Ancak, eğer **kontrolü geçerseniz** ve oturumunuz güvenlik özniteliğinde o "True" değerini alırsa, aynı özniteliğe bağlı **diğer kaynaklara erişmeye çalışabilirsiniz** ama aslında **erişim izniniz olmamalıdır**. [Çözüm](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Kayıt işlevselliği

Zaten var olan bir kullanıcı olarak kayıt olmayı deneyin. Noktaları, çok fazla boşluk ve Unicode karakterlerini kullanarak eşdeğer karakterlerle de deneyin.

### E-postaları ele geçirme

Bir e-posta kaydedin, onaylamadan önce e-postayı değiştirin, sonra eğer yeni onay e-postası ilk kayıtlı e-postaya gönderilirse, herhangi bir e-postayı ele geçirebilirsiniz. Ya da ikinci e-postayı etkinleştirebilir ve ilk e-postayı onaylayabilirseniz, herhangi bir hesabı ele geçirebilirsiniz.

### Şirketlerin Atlassian'ı kullanan iç destek masasına erişim

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE yöntemi

Geliştiriciler, üretim ortamında çeşitli hata ayıklama seçeneklerini devre dışı bırakmayı unutabilirler. Örneğin, HTTP `TRACE` yöntemi tanıgnostik amaçlar için tasarlanmıştır. Etkinleştirilirse, web sunucusu, `TRACE` yöntemini kullanan isteklere, alınan tam isteği yanıt olarak yankılayarak yanıt verecektir. Bu davranış genellikle zararsızdır, ancak bazen, ters proxy'ler tarafından isteklere eklenen dahili kimlik doğrulama başlıklarının adını içeren bilgilerin ifşasına yol açabilir.![Gönderi için resim](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Gönderi için resim](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking hilelerini paylaşmak için **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek katkıda bulunun.

</details>
{% endhint %}
