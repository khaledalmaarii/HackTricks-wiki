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


# CBC - Cipher Block Chaining

CBC modunda **önceki şifrelenmiş blok IV olarak** kullanılır ve bir sonraki blokla XOR işlemi yapılır:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

CBC'yi şifrelemek için **zıt işlemler** yapılır:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Dikkat edilmesi gereken **şifreleme anahtarı** ve **IV** kullanılmasıdır.

# Mesaj Dolgusu

Şifreleme **sabit boyutlu bloklarda** gerçekleştirildiği için genellikle **son bloğu tamamlamak için dolgu** gereklidir.\
Genellikle **PKCS7** kullanılır, bu da bloğu **tamamlamak için gereken byte sayısını tekrarlayan bir dolgu** oluşturur. Örneğin, son blokta 3 byte eksikse, dolgu `\x03\x03\x03` olacaktır.

**8 byte uzunluğunda 2 blok** için daha fazla örneklerimize bakalım:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Son örnekte **son bloğun dolu olduğuna** dikkat edin, bu yüzden sadece dolgu ile başka bir blok oluşturuldu.

# Padding Oracle

Bir uygulama şifrelenmiş verileri şifre çözme işleminden sonra önce veriyi şifre çözecek; ardından dolguyu kaldıracaktır. Dolgu temizliği sırasında, **geçersiz bir dolgu algılanabilir bir davranışı tetiklerse**, bir **padding oracle açığı** oluşur. Algılanabilir davranış bir **hata**, **sonuçların eksikliği** veya **daha yavaş bir yanıt** olabilir.

Bu davranışı tespit ederseniz, **şifrelenmiş verileri şifre çözebilir** ve hatta **herhangi bir açık metni şifreleyebilirsiniz**.

## Nasıl sömürülür

Bu tür bir açığı sömürmek için [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) kullanabilir veya sadece devam edebilirsiniz.
```
sudo apt-get install padbuster
```
Bir sitenin çerezinin savunmasız olup olmadığını test etmek için şunları deneyebilirsiniz:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Kodlama 0**, **base64**'ün kullanıldığı anlamına gelir (ancak diğerleri de mevcuttur, yardım menüsünü kontrol edin).

Bu zafiyeti yeni verileri şifrelemek için de **kötüye kullanabilirsiniz. Örneğin, çerezin içeriğinin "**_**user=MyUsername**_**" olduğunu varsayalım, sonra bunu "\_user=administrator\_" olarak değiştirebilir ve uygulama içinde ayrıcalıkları yükseltebilirsiniz. Ayrıca, `-plaintext` parametresini belirterek `paduster` kullanarak da yapabilirsiniz:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Eğer site savunmasızsa, `padbuster` otomatik olarak dolgu hatası meydana geldiğinde bulmaya çalışacaktır, ancak ayrıca hata mesajını belirtmek için **-error** parametresini de kullanabilirsiniz.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Teori

**Özetle**, şifrelenmiş verileri şifresini çözmeye başlayabilirsiniz, doğru değerleri tahmin ederek **farklı dolgu**ları oluşturmak için kullanılabilecek. Ardından, dolgu oracle saldırısı, hangisinin doğru değeri olacağını tahmin ederek **1, 2, 3 vb. dolgu oluşturan** doğru değeri tahmin ederek baştan sona doğru baytları şifrelemeye başlayacaktır.

![](<../.gitbook/assets/image (629) (1) (1).png>)

**E0'den E15'e** kadar olan baytlar tarafından oluşturulan **2 bloktan** oluşan bazı şifrelenmiş metinler olduğunu hayal edin.\
**Son bloğu** (**E8** ile **E15**) **şifrelemek** için, tüm blok "blok şifre çözme" işleminden geçer ve **ara baytlar I0'dan I15'e** oluşturur.\
Son olarak, her ara bayt önceki şifrelenmiş baytlarla (E0'dan E7'ye) **XOR** edilir. Yani:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Şimdi, `C15` **0x01** olduğunda **`E7` değiştirilebilir** ve bu da doğru bir dolgu olacaktır. Bu durumda: `\x01 = I15 ^ E'7`

Bu nedenle, `E'7` bulunduğunda, **I15 hesaplanabilir**: `I15 = 0x01 ^ E'7`

Bu bize **C15'i hesaplama** olanağı sağlar: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

**C15** bilindiğine göre, şimdi **C14 hesaplanabilir**, ancak bu sefer `\x02\x02` dolgusunu kaba kuvvet uygulayarak.

Bu BF, öncekiyle aynı kadar karmaşıktır çünkü 0x02 değerine sahip `E''15`'i hesaplamak mümkündür: `E''7 = \x02 ^ I15` bu yüzden sadece **`C14`'ü `0x02`'ye eşit olan `E'14`'ü bulmak gereklidir.\
Sonra, C14'ü şifrelemek için aynı adımları uygulayın: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Tüm şifreli metni çözmek için bu zinciri takip edin.**

## Zafiyetin Tespiti

Bir hesap kaydedin ve bu hesapla oturum açın.\
Eğer **çok kez oturum açarsanız** ve her zaman **aynı çerez**i alırsanız, uygulamada muhtemelen **bir sorun** var demektir. Geri gönderilen çerez her oturum açtığınızda **benzersiz olmalıdır**. Eğer çerez **her zaman** **aynıysa**, muhtemelen her zaman geçerli olacak ve **geçersiz kılacak bir yol olmayacaktır**.

Şimdi, çerezi **değiştirmeyi denerseniz**, uygulamadan bir **hata** aldığınızı görebilirsiniz.\
Ancak dolgu (örneğin padbuster kullanarak) kaba kuvvet uygularsanız, farklı bir kullanıcı için geçerli başka bir çerez elde edebilirsiniz. Bu senaryo büyük olasılıkla padbuster'a karşı savunmasızdır.

## Referanslar

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


{% hint style="success" %}
AWS Hacking öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
{% endhint %}
