<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>


# CBC

Eğer **çerez** sadece **kullanıcı adı** ise (veya çerezin ilk kısmı kullanıcı adı ise) ve kullanıcı adını "**admin**" olarak taklit etmek istiyorsanız. O zaman, kullanıcı adını **"bdmin"** olarak oluşturabilir ve çerezin **ilk baytını** **bruteforce** edebilirsiniz.

# CBC-MAC

**Şifre blok zincirleme mesaj doğrulama kodu** (**CBC-MAC**), kriptografi alanında kullanılan bir yöntemdir. Bir mesajı blok blok şifreleyerek çalışır, her bloğun şifrelemesi bir önceki bloğa bağlıdır. Bu süreç, orijinal mesajın sadece bir bitinin bile değişmesinin son şifreli verinin son bloğunda öngörülemeyen bir değişikliğe yol açacağını sağlayan bir **blok zinciri** oluşturur. Böyle bir değişiklik yapmak veya tersine çevirmek için şifreleme anahtarı gereklidir, bu da güvenliği sağlar.

Mesaj m'nin CBC-MAC'ini hesaplamak için, m'yi sıfır başlangıç vektörü ile CBC modunda şifreler ve son bloğu saklar. Aşağıdaki şekil, bir mesajın CBC-MAC'inin hesaplanmasını gösteren bir figürdür![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) gizli anahtar k ve blok şifresi E kullanılarak:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Zafiyet

CBC-MAC ile genellikle **kullanılan IV 0'dır**.\
Bu, 2 bilinen mesajın (`m1` ve `m2`) bağımsız olarak 2 imza (`s1` ve `s2`) oluşturacağı bir sorundur. Yani:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Sonra, m1 ve m2'nin birleştirilmiş olduğu bir mesaj (m3), 2 imza (s31 ve s32) oluşturacaktır:

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Bu, şifrenin anahtarını bilmeden hesaplanabilir.**

8 baytlık bloklar halinde **Yönetici** adını şifrelediğinizi hayal edin:

* `Administ`
* `rator\00\00\00`

**Administ** adında bir kullanıcı oluşturabilir ve imzasını (s1) alabilirsiniz.\
Sonra, `rator\00\00\00 XOR s1` işleminin sonucu olan bir kullanıcı adı oluşturabilirsiniz. Bu, s32 olan `E(m2 XOR s1 XOR 0)`'yi oluşturacaktır.\
şimdi, s32'yi **Yönetici** adının tam imzası olarak kullanabilirsiniz.

### Özet

1. Kullanıcı adının **Administ** (m1) imzasını alın, bu s1'dir
2. Kullanıcı adının **rator\x00\x00\x00 XOR s1 XOR 0** imzasını alın, bu s32'dir**.**
3. Çerezi s32 olarak ayarlayın ve bu, **Yönetici** kullanıcısı için geçerli bir çerez olacaktır.

# Saldırıyı Kontrol Eden IV

Kullanılan IV'yi kontrol edebiliyorsanız, saldırı çok kolay olabilir.\
Eğer çerez sadece şifrelenmiş kullanıcı adı ise, kullanıcıyı "**yönetici**" olarak taklit etmek için **Yönetici** kullanıcısını oluşturabilir ve çerezini alabilirsiniz.\
Şimdi, IV'yi kontrol edebiliyorsanız, IV'nin ilk baytını değiştirebilirsiniz, böylece **IV\[0] XOR "A" == IV'\[0] XOR "a"** olacak ve **Yönetici** kullanıcısı için çerezi yeniden oluşturabilirsiniz. Bu çerez, başlangıçtaki **IV** ile **yönetici** kullanıcısını taklit etmek için geçerli olacaktır.

## Referanslar

Daha fazla bilgi için [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
