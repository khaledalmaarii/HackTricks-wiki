{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin**.
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}


# ECB

(ECB) Elektronik Kod Kitabı - her **açık metin bloğunu** **şifreli metin bloğuyla değiştiren** simetrik şifreleme şemasıdır. Bu, **en basit** şifreleme şemasıdır. Temel fikir, açık metni **N bitlik bloklara bölmek** (giriş verisi bloğunun boyutuna, şifreleme algoritmasına bağlıdır) ve ardından her açık metin bloğunu yalnızca anahtar kullanarak şifrelemektir (şifre çözmek).

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECB kullanmanın birden fazla güvenlik sonucu vardır:

* **Şifreli mesajdan bloklar çıkarılabilir**
* **Şifreli mesajdan bloklar taşınabilir**

# Zafiyetin Tespiti

Bir uygulamaya birkaç kez giriş yaparsınız ve **her zaman aynı çerez** alırsınız. Bu, uygulamanın çerezinin **`<kullanıcı adı>|<şifre>`** olduğu içindir.\
Sonra, **uzun şifreleri olan iki yeni kullanıcı oluşturursunuz**, her ikisinin de **neredeyse** **aynı** **kullanıcı adına** sahip olduğunu fark edersiniz.\
Her iki kullanıcının bilgilerinin olduğu **8B'lik blokların** aynı olduğunu **fark edersiniz**. Bu durumun **ECB kullanıldığından** kaynaklanabileceğini düşünürsünüz.

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

Çerezin formatını bildiğinizde (`<kullanıcı adı>|<şifre>`), `admin` kullanıcısını taklit etmek için `aaaaaaaaadmin` adında yeni bir kullanıcı oluşturun ve çerezi alıp çözümleyin:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Şablonu `\x23U\xE45K\xCB\x21\xC8` içeren kullanıcı adıyla oluşturulan deseni görebiliriz.\
Ardından, ilk 8B bloğunu kaldırabilir ve `admin` kullanıcı adı için geçerli bir çerez elde edebilirsiniz:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Blokları Taşımak

Birçok veritabanında `WHERE username='admin';` veya `WHERE username='admin    ';` aramak aynı sonucu verir _(Ekstra boşluklara dikkat edin)_

Bu nedenle, kullanıcı `admin`yi taklit etmenin başka bir yolu şöyle olabilir:

* `len(<username>) + len(<delimiter) % len(block)` uzunluğunda bir kullanıcı adı oluşturun. `8B` blok boyutuyla `username       ` adında bir kullanıcı adı oluşturabilirsiniz, `|` ayraç ile `<username><delimiter>` parçası 2 adet 8B'lik blok oluşturacaktır.
* Ardından, istediğimiz kullanıcı adını ve boşlukları içeren tam sayıda bloğu dolduracak bir şifre oluşturun, örneğin: `admin   `

Bu kullanıcının çerezi 3 bloktan oluşacaktır: ilk 2 blok kullanıcı adı + ayraç blokları ve üçüncüsü (kullanıcı adını taklit eden) şifre bloğu: `username       |admin   `

**Sonra, sadece ilk bloğu en son blokla değiştirin ve `admin` kullanıcısını taklit etmiş olacaksınız: `admin          |username`**

## Referanslar

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
