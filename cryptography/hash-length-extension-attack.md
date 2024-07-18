{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip et**.
* **Hacking püf noktalarını paylaşmak için PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulun.

</details>
{% endhint %}


# Saldırının Özeti

Bir sunucuyu hayal edin ki **bazı verileri** imzalıyor, bunu yaparken bilinen açık metin verilerine bir **gizli** ekleyip sonra bu veriyi karma işlemine tabi tutuyor. Eğer şunları biliyorsanız:

* **Gizli bilginin uzunluğu** (bu aynı zamanda belirli bir uzunluk aralığından kaba kuvvet saldırısı ile de bulunabilir)
* **Açık metin verisi**
* **Algoritma (ve bu saldırıya karşı savunmasız olması)**
* **Doldurma biliniyor**
* Genellikle varsayılan bir doldurma kullanılır, bu yüzden diğer 3 gereklilik karşılanıyorsa, bu da karşılanır
* Doldurma, gizli veri + veri uzunluğuna bağlı olarak değişir, bu yüzden gizli bilginin uzunluğuna ihtiyaç vardır

O zaman, bir **saldırganın** **veri ekleyip** önceki veri + eklenen veri için geçerli bir **imza oluşturması** mümkündür.

## Nasıl?

Temelde savunmasız algoritmalar, öncelikle bir veri bloğunu karma işlemine tabi tutarak karma değerlerini oluşturur ve ardından, **önceki** oluşturulan **karma** (durum) **veriden** başlayarak **bir sonraki veri bloğunu ekler** ve **karma işlemine tabi tutar**.

Öyleyse, gizli bilginin "gizli" ve verinin "veri" olduğunu hayal edin, "gizliveri"nin MD5'i 6036708eba0d11f6ef52ad44e8b74d5b.\
Bir saldırganın "ekle" dizesini eklemek istemesi durumunda:

* 64 "A"nın MD5'ini oluştur
* Önceden başlatılmış karma işleminin durumunu 6036708eba0d11f6ef52ad44e8b74d5b olarak değiştir
* "ekle" dizesini ekleyin
* Karma işlemini tamamlayın ve elde edilen karma, "gizli" + "veri" + "doldurma" + "ekle" için **geçerli bir** olacaktır

## **Araç**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referanslar

Bu saldırının iyi açıklandığı yeri [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) adresinde bulabilirsiniz.


{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip et**.
* **Hacking püf noktalarını paylaşmak için PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulun.

</details>
{% endhint %}
