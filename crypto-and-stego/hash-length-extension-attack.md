# Hash Length Extension Attack

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Summary of the attack

Bir sunucunun bazı bilinen açık metin verilerine bir **gizli** ekleyerek **imzaladığı** bazı **verileri** hayal edin ve ardından bu verileri hash'lediğini düşünün. Eğer şunları biliyorsanız:

* **Gizlinin uzunluğu** (bu, belirli bir uzunluk aralığından da brute force ile elde edilebilir)
* **Açık metin verisi**
* **Algoritma (ve bu saldırıya karşı savunmasız)**
* **Padding biliniyor**
* Genellikle varsayılan bir padding kullanılır, bu nedenle diğer 3 gereklilik karşılandığında bu da geçerlidir
* Padding, gizli+veri uzunluğuna bağlı olarak değişir, bu yüzden gizlinin uzunluğu gereklidir

O zaman, bir **saldırganın** **veri eklemesi** ve **önceki veri + eklenen veri** için geçerli bir **imza** **üretmesi** mümkündür.

### How?

Temelde, savunmasız algoritmalar hash'leri önce bir **veri bloğunu hash'leyerek** oluşturur ve ardından, **önceden** oluşturulmuş **hash** (durum) üzerinden **bir sonraki veri bloğunu ekleyip** **hash'ler**.

O zaman, gizli "secret" ve veri "data" ise, "secretdata"nın MD5'i 6036708eba0d11f6ef52ad44e8b74d5b'dir.\
Eğer bir saldırgan "append" dizesini eklemek isterse, şunları yapabilir:

* 64 "A"nın MD5'ini oluştur
* Önceden başlatılmış hash'in durumunu 6036708eba0d11f6ef52ad44e8b74d5b olarak değiştir
* "append" dizesini ekle
* Hash'i tamamla ve sonuçta elde edilen hash, **"secret" + "data" + "padding" + "append"** için geçerli olacaktır

### **Tool**

{% embed url="https://github.com/iagox86/hash_extender" %}

### References

Bu saldırıyı iyi bir şekilde açıklanmış olarak [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) adresinde bulabilirsiniz.



{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
