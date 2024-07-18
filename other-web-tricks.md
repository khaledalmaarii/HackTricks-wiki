# Diğer Web Hileleri

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya **bizi** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** Twitter'da takip edin.**
* **Hacking hilelerini paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
{% endhint %}

### Ana bilgisayar başlığı

Arka uç bazen bazı işlemleri gerçekleştirmek için **Ana Bilgisayar başlığına** güvenir. Örneğin, şifre sıfırlama bağlantısı göndermek için değerini kullanabilir. Bu nedenle, şifrenizi sıfırlamak için bir bağlantı içeren bir e-posta aldığınızda, kullanılan alan, Ana Bilgisayar başlığına koyduğunuz alandır. Sonra, diğer kullanıcıların şifre sıfırlama isteğini isteyebilir ve alanı kendi kontrolünüzde olan bir alana değiştirerek şifre sıfırlama kodlarını çalmaya çalışabilirsiniz. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Kullanıcıların sıfırlama bağlantısına tıklamasını beklemenize gerek olmadığını unutmayın, çünkü belki de **spam filtreleri veya diğer aracı cihazlar/botlar analiz etmek için tıklar**.
{% endhint %}

### Oturum boole'ları

Bazen doğrulamayı doğru bir şekilde tamamladığınızda, arka uç **oturumunuzdaki bir güvenlik özniteliğine "True" değerini ekleyebilir**. Sonra, farklı bir uç nokta, o kontrolü başarıyla geçip geçmediğinizi bilecektir.\
Ancak, eğer **kontrolü geçerseniz** ve oturumunuz güvenlik özniteliğinde "True" değerini alırsa, **aynı özniteliğe bağlı** ancak **erişim izniniz olmaması gereken** diğer kaynaklara **erişmeye çalışabilirsiniz**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Kayıt işlevselliği

Zaten var olan bir kullanıcı olarak kayıt olmayı deneyin. Noktalar, çok fazla boşluk ve Unicode gibi eşdeğer karakterleri de kullanmayı deneyin.

### E-postaları ele geçirme

Bir e-posta kaydedin, onaylamadan önce e-postayı değiştirin, sonra, yeni onay e-postası ilk kayıtlı e-postaya gönderilirse, herhangi bir e-postayı ele geçirebilirsiniz. Ya da ikinci e-postayı etkinleştirebilirseniz, ilkini onaylayarak herhangi bir hesabı ele geçirebilirsiniz.

### Şirketlerin Atlassian'ı kullanan iç destek masasına erişim

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE yöntemi

Geliştiriciler, üretim ortamında çeşitli hata ayıklama seçeneklerini devre dışı bırakmayı unutabilirler. Örneğin, HTTP `TRACE` yöntemi tanıgnostik amaçlar için tasarlanmıştır. Etkinleştirildiğinde, web sunucusu, `TRACE` yöntemini kullanan isteklere yanıt vererek aldığı tam isteği yanıt olarak yansıtacaktır. Bu davranış genellikle zararsızdır, ancak bazen, ters proxy'ler tarafından isteklere eklenen dahili kimlik doğrulama başlıklarının adı gibi bilgilerin ifşasına yol açabilir.![Gönderi için resim](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Gönderi için resim](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya **bizi** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** Twitter'da takip edin.**
* **Hacking hilelerini paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
{% endhint %}
