# Hash Length Extension Attack

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), bir şirketin veya müşterilerinin **stealer malwares** tarafından **tehdit edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan bir **dark-web** destekli arama motorudur.

WhiteIntel'in ana hedefi, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Web sitelerini kontrol edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## Saldırının Özeti

Bir sunucunun bazı **verileri** **gizli** bir bilgiyi bilinen düz metin verisine **ekleyerek** **imzaladığını** ve ardından bu veriyi hash'lediğini hayal edin. Eğer şunları biliyorsanız:

* **Gizli bilginin uzunluğu** (bu, belirli bir uzunluk aralığından da brute force ile elde edilebilir)
* **Düz metin verisi**
* **Algoritma (ve bu saldırıya karşı savunmasız)**
* **Padding biliniyor**
* Genellikle varsayılan bir padding kullanılır, bu nedenle diğer 3 gereklilik karşılandığında bu da geçerlidir
* Padding, gizli bilgi + veri uzunluğuna bağlı olarak değişir, bu yüzden gizli bilginin uzunluğu gereklidir

O zaman, bir **saldırganın** **veri ekleyip** **önceki veri + eklenen veri** için geçerli bir **imza** **üretmesi** mümkündür.

### Nasıl?

Temelde, savunmasız algoritmalar hash'leri önce bir **veri bloğunu hash'leyerek** oluşturur ve ardından, **önceden** oluşturulmuş **hash** (durum) üzerinden **bir sonraki veri bloğunu ekleyip** **hash'ler**.

O zaman, gizli bilgi "secret" ve veri "data" ise, "secretdata"nın MD5'i 6036708eba0d11f6ef52ad44e8b74d5b'dir.\
Eğer bir saldırgan "append" dizesini eklemek isterse, şunları yapabilir:

* 64 "A" karakterinin MD5'ini oluştur
* Önceden başlatılmış hash'in durumunu 6036708eba0d11f6ef52ad44e8b74d5b olarak değiştir
* "append" dizesini ekle
* Hash'i tamamla ve sonuçta elde edilen hash, **"secret" + "data" + "padding" + "append"** için geçerli olacaktır.

### **Araç**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Referanslar

Bu saldırıyı [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) adresinde iyi bir şekilde bulabilirsiniz.

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), bir şirketin veya müşterilerinin **stealer malwares** tarafından **tehdit edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan bir **dark-web** destekli arama motorudur.

WhiteIntel'in ana hedefi, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Web sitelerini kontrol edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
