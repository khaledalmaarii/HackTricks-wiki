<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>


# ECB

(ECB) Elektronik Kod Kitabı - her **açık metin bloğunu** **şifreli blokla** değiştiren **simetrik şifreleme düzeni**. Bu, **en basit** şifreleme düzenidir. Temel fikir, açık metni **N bitlik bloklara bölmek** (giriş verisi bloğunun boyutuna, şifreleme algoritmasına bağlıdır) ve ardından yalnızca anahtar kullanarak her açık metin bloğunu şifrelemek (şifre çözmek) için.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECB kullanmanın birden fazla güvenlik sonucu vardır:

* **Şifreli mesajdan bloklar çıkarılabilir**
* **Şifreli mesajdan bloklar yer değiştirebilir**

# Zafiyetin Tespiti

Bir uygulamaya birkaç kez giriş yaparsınız ve **her zaman aynı çerez** alırsınız. Bu, uygulamanın çerezinin **`<kullanıcı adı>|<şifre>`** olduğu içindir.\
Ardından, **uzun şifreleri olan iki yeni kullanıcı oluşturursunuz**, her ikisinin de **neredeyse** **aynı** **kullanıcı adına** sahip olduğunu fark edersiniz.\
Her iki kullanıcının bilgilerinin olduğu **8B'lik blokların** aynı olduğunu fark edersiniz. Bu durumun **ECB kullanıldığından** olabileceğini düşünürsünüz.

Aşağıdaki örnekte olduğu gibi. İki **çözülmüş çerezin** birden fazla kez **`\x23U\xE45K\xCB\x21\xC8`** bloğuna sahip olduğunu gözlemleyin.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Bu, çerezlerin **kullanıcı adı ve şifresinin "a" harfini birkaç kez içerdiği** için oldu (örneğin). **Farklı** olan bloklar, **en az 1 farklı karakter içeren bloklardır** (belki ayraç "|" veya kullanıcı adındaki bazı gerekli farklılık).

Şimdi, saldırgan sadece formatın `<kullanıcı adı><ayraç><şifre>` veya `<şifre><ayraç><kullanıcı adı>` olduğunu keşfetmesi gerekiyor. Bunu yapmak için, **benzer ve uzun kullanıcı adları ve şifreler içeren birkaç kullanıcı adı oluşturarak formatı ve ayraç uzunluğunu bulana kadar denemeler yapabilir:**

| Kullanıcı adı uzunluğu: | Şifre uzunluğu: | Kullanıcı adı+Şifre uzunluğu: | Çerez uzunluğu (çözümlendikten sonra): |
| ---------------------- | ---------------- | ---------------------------- | ------------------------------------- |
| 2                      | 2                | 4                            | 8                                     |
| 3                      | 3                | 6                            | 8                                     |
| 3                      | 4                | 7                            | 8                                     |
| 4                      | 4                | 8                            | 16                                    |
| 7                      | 7                | 14                           | 16                                    |

# Zafiyetin Sömürülmesi

## Tüm blokların kaldırılması

Çerezin formatını bildiğinizde (`<kullanıcı adı>|<şifre>`), `admin` kullanıcısını taklit etmek için `aaaaaaaaadmin` adında yeni bir kullanıcı oluşturun ve çerezi alın ve çözümleyin:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Önceki olarak yalnızca `a` içeren kullanıcı adı ile oluşturulan `\x23U\xE45K\xCB\x21\xC8` desenini görebiliriz.\
Sonra, ilk 8B bloğunu kaldırabilir ve `admin` kullanıcı adı için geçerli bir çerez elde edersiniz:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Blokları Taşımak

Birçok veritabanında `WHERE username='admin';` veya `WHERE username='admin    ';` aramak aynı sonucu verir _(Ekstra boşluklara dikkat)_

Bu nedenle, kullanıcı `admin`yi taklit etmenin başka bir yolu şöyle olabilir:

* `len(<username>) + len(<delimiter) % len(block)` uzunluğunda bir kullanıcı adı oluşturun. `8B` blok boyutuyla `username       ` adında bir kullanıcı adı ve `|` ayraçla `<username><delimiter>` parçası 2 adet 8B'lik blok oluşturacaktır.
* Ardından, taklit etmek istediğimiz kullanıcı adını ve boşlukları içeren tam sayıda bloğu dolduracak bir şifre oluşturun, örneğin: `admin   `

Bu kullanıcının çerezi 3 bloktan oluşacaktır: ilk 2 blok kullanıcı adı + ayraç blokları ve üçüncüsü (kullanıcı adını taklit eden) şifre bloğu: `username       |admin   `

**Sonra, sadece ilk bloğu son blokla değiştirin ve `admin` kullanıcısını taklit etmiş olacaksınız: `admin          |username`**

## Referanslar

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
