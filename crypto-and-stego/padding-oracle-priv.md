# Padding Oracle

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>

## CBC - Şifre Blok Zinciri

CBC modunda, **önceki şifrelenmiş blok bir IV** olarak kullanılır ve bir sonraki blokla XOR işlemi yapılır:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

CBC'yi şifrelemek için **ters** **işlemler** yapılır:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Dikkat edilmesi gereken nokta, bir **şifreleme anahtarı** ve bir **IV** kullanılmasıdır.

## Mesaj Dolgusu

Şifreleme **sabit** **boyutlu bloklar** halinde gerçekleştirildiği için, genellikle **son** **bloğu tamamlamak** için **dolguya** ihtiyaç duyulur.\
Genellikle **PKCS7** kullanılır ve bloğu tamamlamak için gereken **bayt sayısını tekrarlayan bir dolgu** oluşturur. Örneğin, son blokta eksik olan 3 bayt ise dolgu `\x03\x03\x03` olacaktır.

**8 baytlık 2 blok** ile daha fazla örneğe bakalım:

| bayt #0 | bayt #1 | bayt #2 | bayt #3 | bayt #4 | bayt #5 | bayt #6 | bayt #7 | bayt #0  | bayt #1  | bayt #2  | bayt #3  | bayt #4  | bayt #5  | bayt #6  | bayt #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Son örnekte **son blok dolu olduğu için sadece dolguyla başka bir blok oluşturuldu**.

## Dolgu Oracle

Bir uygulama şifrelenmiş verileri çözerken, önce verileri çözer; ardından dolguyu kaldırır. Dolgu temizliği sırasında, **geçersiz bir dolgu algılanabilir bir davranışı tetiklerse**, bir **dolgu oracle zafiyeti** vardır. Algılanabilir davranış bir **hata**, **sonuç eksikliği** veya **daha yavaş bir yanıt** olabilir.

Bu davranışı tespit ederseniz, **şifrelenmiş verileri çözebilir** ve hatta **herhangi bir açık metni şifreleyebilirsiniz**.

### Nasıl sömürülür

Bu tür bir zafiyeti sömürmek için [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) kullanabilir veya sadece şunları yapabilirsiniz

```
sudo apt-get install padbuster
```

Bir sitenin çerezinin savunmasız olup olmadığını test etmek için şunları deneyebilirsiniz:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

**Kodlama 0**, **base64** kullanıldığı anlamına gelir (ancak diğerleri de mevcuttur, yardım menüsünü kontrol edin).

Ayrıca, bu zafiyeti yeni verileri şifrelemek için **kötüye kullanabilirsiniz**. Örneğin, çerezin içeriği "**\_**user=MyUsername**\_**" ise, bunu "\_user=administrator\_" olarak değiştirebilir ve uygulama içinde ayrıcalıkları yükseltebilirsiniz. Aynı işlemi `-plaintext` parametresini belirterek `paduster` kullanarak da yapabilirsiniz:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```

Eğer site savunmasızsa, `padbuster` otomatik olarak hata oluştuğunda bunu bulmaya çalışacaktır, ancak hata mesajını da **-error** parametresini kullanarak belirtebilirsiniz.

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```

### Teori

**Özet olarak**, farklı dolguları oluşturmak için kullanılabilecek doğru değerleri tahmin ederek şifrelenmiş verilerin şifresini çözmeye başlayabilirsiniz. Ardından, dolgu orak saldırısı, doğru değeri tahmin ederek 1, 2, 3 vb. bir dolgu oluşturan doğru değeri tahmin ederek, sona doğru baytları şifrelemeye başlar.

![](<../.gitbook/assets/image (629) (1) (1).png>)

E0 ile E15 arasındaki baytlardan oluşan **2 blok** şeklinde olan bazı şifrelenmiş metinlere sahip olduğunuzu hayal edin.\
**Son** **bloğu** (**E8** ile **E15**) **şifrelemek** için, tüm blok "blok şifre çözme" işleminden geçer ve ara baytlar I0 ile I15 oluşturur.\
Son olarak, her ara bayt önceki şifrelenmiş baytlarla (E0 ile E7) **XOR** edilir. Yani:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Şimdi, `C15` `0x01` olduğunda `E7` değiştirilebilir, bu da doğru bir dolgu olacaktır. Bu durumda: `\x01 = I15 ^ E'7`

Bu nedenle, E'7 bulunarak I15 hesaplanabilir: `I15 = 0x01 ^ E'7`

Bu bize C15'i hesaplama olanağı sağlar: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

C15'i bildikten sonra, bu sefer `\x02\x02` dolgusunu brute-force yaparak C14'ü hesaplamak mümkündür.

Bu brute-force, öncekine benzer karmaşıklığa sahiptir çünkü 0x02 değerine sahip olan E''15'i hesaplamak mümkündür: `E''7 = \x02 ^ I15`, bu yüzden sadece C14'ü 0x02'ye eşit olan E'14'ü bulmak gerekmektedir.\
Sonra, şifrelemeyi çözmek için aynı adımları C14 için yapın: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Tüm şifreli metni çözmek için bu zinciri takip edin.**

### Zafiyetin Tespiti

Bir hesap kaydedin ve bu hesapla oturum açın.\
Eğer birçok kez oturum açarsanız ve her seferinde **aynı çerez** alırsanız, uygulamada muhtemelen **bir şeyler yanlış**. Her oturum açtığınızda çerezin **benzersiz olması** gerekir. Eğer çerez **her zaman** **aynı** ise, muhtemelen her zaman geçerli olacak ve **geçersiz kılmanın bir yolu olmayacak**.

Şimdi, çerezi **değiştirmeye** çalışırsanız, uygulamadan bir **hata** aldığınızı görebilirsiniz.\
Ancak, padbuster gibi bir araç kullanarak dolgu değerini brute-force yaparsanız, farklı bir kullanıcı için geçerli olan başka bir çerez elde edebilirsiniz. Bu senaryo, padbuster için büyük olasılıkla savunmasızdır.

### Referanslar

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github reposuna **PR göndererek paylaşın**.

</details>
