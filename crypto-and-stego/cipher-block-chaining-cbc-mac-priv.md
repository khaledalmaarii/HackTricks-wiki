<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** üzerinden bizi takip edin 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# CBC

Eğer **çerez** sadece **kullanıcı adı**dır (veya çerezin ilk kısmı kullanıcı adıdır) ve kullanıcı adını "**admin**" olarak taklit etmek istiyorsanız. O zaman, **"bdmin"** kullanıcı adını oluşturabilir ve çerezin **ilk baytını** brute force yöntemiyle bulabilirsiniz.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**), kriptografi alanında kullanılan bir yöntemdir. Bu yöntem, bir mesajı blok blok şifreleyerek çalışır, her bloğun şifrelemesi bir önceki bloğa bağlıdır. Bu süreç, orijinal mesajın sadece bir bitinin bile değiştirilmesinin şifrelenmiş verinin son bloğunda tahmin edilemez bir değişikliğe yol açacağından emin olmak için bir **blok zinciri** oluşturur. Böyle bir değişiklik yapmak veya tersine çevirmek için şifreleme anahtarı gereklidir, bu da güvenliği sağlar.

Mesaj m'nin CBC-MAC'ini hesaplamak için, m'yi sıfır başlangıç vektörüyle CBC modunda şifreler ve son bloğu saklar. Aşağıdaki şekil, bir gizli anahtar k ve bir blok şifreleme E kullanılarak bloklardan oluşan bir mesajın CBC-MAC'inin hesaplanmasını taslak olarak gösterir:

![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) kullanılarak CBC-MAC'in hesaplanması

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Zafiyet

CBC-MAC ile genellikle kullanılan **IV 0'dır**.\
Bu bir sorundur çünkü bağımsız olarak bilinen 2 mesaj (`m1` ve `m2`), 2 imza (`s1` ve `s2`) oluşturur. Yani:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Sonra, m1 ve m2'nin birleştirildiği bir mesaj (m3), 2 imza (s31 ve s32) oluşturur:

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Bu, şifrelemenin anahtarını bilmeden hesaplanabilir.**

8 baytlık bloklar halinde **Yönetici** adını şifrelediğinizi hayal edin:

* `Administ`
* `rator\00\00\00`

**Administ** (m1) adında bir kullanıcı adı oluşturabilir ve imzasını (s1) alabilirsiniz.\
Ardından, `rator\00\00\00 XOR s1 XOR 0`'ın sonucu olan bir kullanıcı adı oluşturabilirsiniz. Bu, `E(m2 XOR s1 XOR 0)`'i üretecektir ve bu da s32'yi oluşturur.\
Şimdi, s32'yi **Yönetici** adının imzası olarak kullanabilirsiniz.

### Özet

1. Kullanıcı adı **Administ** (m1) imzasını (s1) alın
2. Kullanıcı adı **rator\x00\x00\x00 XOR s1 XOR 0**'ın imzasını (s32) alın.
3. Çerezi s32 olarak ayarlayın ve bu, **Yönetici** kullanıcısı için geçerli bir çerez olacaktır.

# Saldırıyı Kontrol Eden IV

Eğer kullanılan IV'yi kontrol edebiliyorsanız, saldırı çok kolay olabilir.\
Eğer çerezler sadece şifrelenmiş kullanıcı adı ise, kullanıcıyı "**administrator**" olarak taklit etmek için kullanıcıyı "**Yönetici**" olarak oluşturabilir ve onun çerezini alabilirsiniz.\
Şimdi, IV'yi kontrol edebiliyorsanız, IV'nin ilk baytını değiştirebilirsiniz, böylece **IV\[0] XOR "A" == IV'\[0] XOR "a"** olur ve **Yönetici** kullanıcısı için çerezi yeniden oluşturabilirsiniz. Bu çerez, başlangıçtaki IV ile **administrator** kullanıcısını **taklit etmek** için geçerli olacaktır.

## Referanslar

Daha fazla bilgi için [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC) adresini ziyaret edin.


<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** üzerinden bizi takip edin 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
