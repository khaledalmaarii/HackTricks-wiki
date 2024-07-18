{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip et.**
* **Hacking püf noktalarını paylaşmak için PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulun.

</details>
{% endhint %}


# CBC

Eğer **çerez** sadece **kullanıcı adı** (veya çerezin ilk kısmı kullanıcı adı ise) ise ve kullanıcı adını "**admin**" olarak taklit etmek istiyorsanız. O zaman, kullanıcı adını **"bdmin"** olarak oluşturabilir ve çerezin **ilk byte'ını** **bruteforce** edebilirsiniz.

# CBC-MAC

**Şifre blok zincirleme mesaj doğrulama kodu** (**CBC-MAC**), kriptografi alanında kullanılan bir yöntemdir. Bir mesajı blok blok şifreleyerek çalışır, her bloğun şifrelemesi bir önceki bloğa bağlıdır. Bu süreç, orijinal mesajın sadece bir bitinin bile değiştirilmesinin şifrelenmiş verinin son bloğunda öngörülemeyen bir değişikliğe yol açacağından emin olmak için bir **blok zinciri** oluşturur. Böyle bir değişiklik yapmak veya tersine çevirmek için şifreleme anahtarı gereklidir, bu da güvenliği sağlar.

Mesaj m'nin CBC-MAC'ini hesaplamak için, m'yi sıfır başlangıç vektörü ile CBC modunda şifreler ve son bloğu saklar. Aşağıdaki şekil, bir mesajın bloklardan oluşan CBC-MAC'inin hesaplanmasını göstermektedir![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) gizli anahtar k ve blok şifresi E kullanılarak:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Zayıflık

CBC-MAC ile genellikle **0 kullanılan IV**'dir.\
Bu bir problemdir çünkü 2 bilinen mesaj (`m1` ve `m2`) bağımsız olarak 2 imza (`s1` ve `s2`) oluşturacaktır. Bu durumda:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Sonra m1 ve m2'nin birleştirilmiş olduğu bir mesaj (m3) 2 imza oluşturacaktır (s31 ve s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Bu, şifrenin anahtarını bilmeden hesaplanabilir.**

8 byte'lık bloklar halinde **Yönetici** adını şifrelediğinizi hayal edin:

* `Administ`
* `rator\00\00\00`

**Administ** adında bir kullanıcı oluşturabilir ve imzasını (s1) alabilirsiniz.\
Sonra, `rator\00\00\00 XOR s1` işleminin sonucu olan bir kullanıcı adı oluşturabilirsiniz. Bu, s32 olan `E(m2 XOR s1 XOR 0)`'yi oluşturacaktır.\
şimdi, s32'yi **Yönetici** adının tam imzası olarak kullanabilirsiniz.

### Özet

1. Kullanıcı adı **Administ** (m1) için imzayı alın, bu s1'dir
2. Kullanıcı adı **rator\x00\x00\x00 XOR s1 XOR 0** için imzayı alın, bu s32'dir.
3. Çerezi s32 olarak ayarlayın ve bu, **Yönetici** kullanıcısı için geçerli bir çerez olacaktır.

# Saldırıyı Kontrol Eden IV

Kullanılan IV'yi kontrol edebiliyorsanız, saldırı çok kolay olabilir.\
Eğer çerez sadece şifrelenmiş kullanıcı adı ise, kullanıcıyı "**yönetici**" olarak taklit etmek için **Yönetici** kullanıcısını oluşturabilir ve onun çerezini alabilirsiniz.\
Şimdi, IV'yi kontrol edebiliyorsanız, IV'nin ilk Byte'ını değiştirebilirsiniz, böylece **IV\[0] XOR "A" == IV'\[0] XOR "a"** ve **Yönetici** kullanıcısı için çerezi yeniden oluşturabilirsiniz. Bu çerez, başlangıçtaki **IV** ile **yönetici** kullanıcısını **taklit etmek** için geçerli olacaktır.

## Referanslar

Daha fazla bilgi için [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip et.**
* **Hacking püf noktalarını paylaşmak için PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulun.

</details>
{% endhint %}
