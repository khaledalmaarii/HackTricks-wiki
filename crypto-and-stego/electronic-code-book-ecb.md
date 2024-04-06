<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# ECB

(ECB) Elektronik Kod Kitabı - her bir **açık metin bloğunu** **şifreli metin bloğuyla değiştiren** simetrik şifreleme şemasıdır. En **basit** şifreleme şemasıdır. Temel fikir, açık metni **N bitlik bloklara** (giriş veri bloğu boyutuna, şifreleme algoritmasına bağlı olarak) bölmek ve ardından yalnızca anahtar kullanarak her bir açık metin bloğunu şifrelemek (şifresini çözmek) için kullanmaktır.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECB kullanmanın birden fazla güvenlik etkisi vardır:

* **Şifreli mesajdan bloklar çıkarılabilir**
* **Şifreli mesajdan bloklar yer değiştirebilir**

# Zafiyetin Tespiti

Bir uygulamaya birkaç kez giriş yaparsınız ve **her seferinde aynı çerez** alırsınız. Bu, uygulamanın çerezi **`<kullanıcı adı>|<parola>`** şeklindedir.\
Sonra, **aynı uzun parolaya** sahip **iki yeni kullanıcı** oluşturursunuz ve **neredeyse** **aynı** **kullanıcı adına** sahiptirler.\
Her iki kullanıcının bilgilerinin aynı olduğu **8B bloklarının eşit olduğunu** fark edersiniz. Bu durumda, bunun **ECB kullanıldığından** kaynaklanabileceğini düşünürsünüz.

Aşağıdaki örnekte olduğu gibi. İki **çözülmüş çerezin** birden çok kez **`\x23U\xE45K\xCB\x21\xC8`** bloğuna sahip olduğunu gözlemleyin.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Bu, çerezlerin kullanıcı adı ve şifresinin birkaç kez "a" harfi içerdiği anlamına gelir (örneğin). Farklı olan bloklar, en az 1 farklı karakter içeren bloklardır (belki de ayraç "|" veya kullanıcı adında gerekli farklılık gibi).

Şimdi, saldırgan sadece formatın `<kullanıcı adı><ayraç><şifre>` veya `<şifre><ayraç><kullanıcı adı>` olduğunu keşfetmesi gerekiyor. Bunun için, benzer ve uzun kullanıcı adları ve şifrelerle birkaç kullanıcı adı oluşturarak formatı ve ayraçın uzunluğunu bulana kadar deneyebilir:

| Kullanıcı adı uzunluğu: | Şifre uzunluğu: | Kullanıcı adı+Şifre uzunluğu: | Çerezin uzunluğu (çözümlendikten sonra): |
| --------------------- | --------------- | --------------------------- | ------------------------------------- |
| 2                     | 2               | 4                           | 8                                     |
| 3                     | 3               | 6                           | 8                                     |
| 3                     | 4               | 7                           | 8                                     |
| 4                     | 4               | 8                           | 16                                    |
| 7                     | 7               | 14                          | 16                                    |

# Zafiyetin sömürülmesi

Çerezin formatını (`<kullanıcı adı>|<şifre>`) bildiğimizde, `admin` kullanıcı adını taklit etmek için `aaaaaaaaadmin` adında yeni bir kullanıcı oluşturun ve çerezi alıp çözümleyin:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Önceden yaratılan `\x23U\xE45K\xCB\x21\xC8` desenini sadece `a` içeren kullanıcı adıyla görebiliriz.\
Ardından, ilk 8B bloğunu kaldırabilirsiniz ve `admin` kullanıcı adı için geçerli bir çerez elde edersiniz:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Blokları Taşımak

Birçok veritabanında `WHERE username='admin';` veya `WHERE username='admin    ';` _(Ekstra boşluklara dikkat edin)_, arama yapmak aynı anlama gelir.

Bu nedenle, `admin` kullanıcısını taklit etmek için başka bir yol şu şekilde olabilir:

* `len(<username>) + len(<delimiter) % len(block)` şeklinde bir kullanıcı adı oluşturun. `8B` blok boyutuyla `username       ` adında bir kullanıcı adı oluşturabilirsiniz. `|` ayırıcı ile `<username><delimiter>` parçası 2 adet 8B blok oluşturacaktır.
* Ardından, kullanıcıyı taklit etmek istediğimiz kullanıcı adını ve boşlukları içeren tam bir blok sayısı oluşturan bir şifre oluşturun, örneğin: `admin   `

Bu kullanıcının çerezi 3 bloktan oluşacaktır: ilk 2 blok kullanıcı adı + ayırıcı blokları ve üçüncü blok (kullanıcı adını taklit eden şifre): `username       |admin   `

**Sonra, sadece ilk bloğu son blokla değiştirin ve `admin` kullanıcısını taklit edeceksiniz: `admin          |username`**

## Referanslar

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
