# ACL'ler - DACL'ler/SACL'ler/ACE'ler

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u takip edin.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>

## **Erişim Kontrol Listesi (ACL)**

Bir Erişim Kontrol Listesi (ACL), bir nesne ve özellikleri için korumaları belirleyen sıralı bir Erişim Kontrol Girişleri (ACE'ler) kümesinden oluşur. Temel olarak, bir ACL, hangi eylemlerin hangi güvenlik prensipleri (kullanıcılar veya gruplar) tarafından bir nesne üzerinde izin verildiği veya reddedildiği belirler.

İki tür ACL vardır:

- **İstek Üzerine Erişim Kontrol Listesi (DACL):** Bir nesneye hangi kullanıcıların ve grupların erişimi olduğunu veya olmadığını belirtir.
- **Sistem Erişim Kontrol Listesi (SACL):** Bir nesneye erişim denemelerinin denetimini yönetir.

Bir dosyaya erişme süreci, sistem tarafından nesnenin güvenlik tanımının kullanıcının erişim belirteciyle karşılaştırılmasıyla gerçekleştirilir ve erişimin, ACE'ler temelinde hangi erişimlerin verileceği ve bu erişimin kapsamı belirlenir.

### **Ana Bileşenler**

- **DACL:** Bir nesne için kullanıcılara ve gruplara erişim izinlerini veren veya reddeden ACE'leri içerir. Temel olarak, erişim haklarını belirleyen ana ACL'dir.

- **SACL:** Nesnelere erişimi denetlemek için kullanılan, ACE'lerin Güvenlik Olay Günlüğü'ne kaydedilecek erişim türlerini tanımladığı bir denetim listesidir. Yetkisiz erişim girişimlerini tespit etmek veya erişim sorunlarını gidermek için son derece değerli olabilir.

### **ACL'lerin Sistemle Etkileşimi**

Her kullanıcı oturumu, kullanıcı, grup kimlikleri ve ayrıcalıklar dahil olmak üzere oturumla ilgili güvenlik bilgilerini içeren bir erişim belirteciyle ilişkilendirilir. Bu belirteç ayrıca oturumu benzersiz bir şekilde tanımlayan bir oturum SID'sini içerir.

Yerel Güvenlik Otoritesi (LSASS), erişim taleplerini nesnelere işleyerek, erişimi denemeye çalışan güvenlik prensibiyle eşleşen ACE'leri DACL'ye bakarak işler. İlgili ACE'ler bulunmadığında erişim hemen sağlanır. Aksi takdirde, LSASS ACE'leri erişim belirtecindeki güvenlik prensibinin SID'siyle karşılaştırarak erişim uygunluğunu belirler.

### **Özetlenmiş Süreç**

- **ACL'ler:** DACL'ler aracılığıyla erişim izinlerini ve SACL'ler aracılığıyla denetim kurallarını tanımlar.
- **Erişim Belirteci:** Bir oturum için kullanıcı, grup ve ayrıcalık bilgilerini içerir.
- **Erişim Kararı:** DACL ACE'leri erişim belirteciyle karşılaştırılarak alınır; denetim için SACL'ler kullanılır.


### ACE'ler

Üç ana **Erişim Kontrol Girişi (ACE)** türü vardır:

- **Erişim Reddedildi ACE'si**: Bu ACE, belirtilen kullanıcılar veya gruplar için bir nesneye erişimi açıkça reddeder (DACL'de).
- **Erişim İzin Verilen ACE'si**: Bu ACE, belirtilen kullanıcılar veya gruplar için bir nesneye erişimi açıkça verir (DACL'de).
- **Sistem Denetimi ACE'si**: Bir Sistem Erişim Kontrol Listesi (SACL) içinde konumlandırılan bu ACE, kullanıcılar veya gruplar tarafından bir nesneye erişim denemeleri sırasında denetim günlüklerini oluşturur. Erişimin izin verilip verilmediğini ve erişimin niteliğini belgeler.

Her ACE'nin **dört temel bileşeni** vardır:

1. Kullanıcının veya grubun **Güvenlik Tanımlayıcısı (SID)** (veya grafiksel bir temsilindeki prensip adı).
2. ACE türünü (erişim reddedildi, izin verildi veya sistem denetimi) tanımlayan bir **bayrak**.
3. Çocuk nesnelerin ebeveynlerinden ACE'yi devralıp devralamayacağını belirleyen **miras bayrakları**.
4. Nesnenin verilen haklarını belirleyen bir **[erişim maskesi](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**, nesnenin verilen haklarını belirleyen 32 bitlik bir değer.

Erişim belirleme, her ACE'yi sırayla inceleyerek gerçekleştirilir, ta ki:

- Bir **Erişim Reddedildi ACE'si**, erişim belirtecindeki bir güvenilir kişiye istenen hakları açıkça reddeder.
- **Erişim İzin Verilen ACE(ler)**, erişim belirtecindeki bir güvenilir kişiye istenen tüm hakları açıkça verir.
- Tüm ACE'ler kontrol edildikten sonra, herhangi bir istenen hak **açıkça izin verilmemişse**, erişim **örtük olarak reddedilir**.


### ACE'lerin Sırası

**ACE'lerin** (bir şeye kimin erişebileceğini veya erişemeyeceğini söyleyen kurallar) **DACL** adı verilen bir listede nasıl yerleştirildiği çok önemlidir. Çünkü sistem bu kurallara dayanarak erişimi verir veya reddederken, geri kalanına bakmayı bırakır.

Bu ACE'leri düzenlemenin en iyi yolu **"kanonik sıra"** olarak adlandırılır. Bu yöntem, her şeyin sorunsuz ve adil bir şekilde çalışmasını sağlamaya yardımcı olur. İşte **Windows 2000** ve **
### GUI Örneği

**[Buradan örnek alınmıştır](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

Bu, ACL, DACL ve ACE'leri gösteren bir klasörün klasik güvenlik sekmesidir:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

**Gelişmiş düğmesine** tıklarsak, miras gibi daha fazla seçenek elde ederiz:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Ve bir Güvenlik İlkesi ekler veya düzenlerseniz:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Son olarak, Denetim sekmesinde SACL'ye sahibiz:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Erişim Kontrolünü Basitleştirilmiş Bir Şekilde Açıklama

Bir klasör gibi kaynaklara erişimi yönetirken, Erişim Kontrol Listeleri (ACL'ler) ve Erişim Kontrol Girişleri (ACE'ler) olarak bilinen listeler ve kurallar kullanırız. Bunlar, belirli verilere kimin erişebileceğini veya erişemeyeceğini tanımlar.

#### Belirli Bir Gruba Erişimi Engelleme

Diyelim ki Cost adında bir klasörünüz var ve herkesin erişmesini istiyorsunuz, ancak pazarlama ekibinin erişimini istemiyorsunuz. Kuralları doğru bir şekilde ayarlayarak, pazarlama ekibine erişimi açmadan önce pazarlama ekibine özel olarak erişimi reddedebiliriz. Bunun için pazarlama ekibine erişimi engelleme kuralını, herkese erişimi sağlayan kuralın önüne yerleştiririz.

#### Engellenen Bir Grubun Belirli Bir Üyesine Erişim İzin Verme

Diyelim ki pazarlama direktörü Bob, genellikle pazarlama ekibinin erişimi olmamasına rağmen Cost klasörüne erişime ihtiyaç duyuyor. Pazarlama ekibine erişimi engelleyen kuralın önüne, Bob'a erişim sağlayan özel bir kural (ACE) ekleyebiliriz. Böylece, Bob, ekibinin genel kısıtlamasına rağmen erişim elde eder.

#### Erişim Kontrol Girişlerini Anlama

ACE'ler, ACL'deki bireysel kurallardır. Kullanıcıları veya grupları tanımlar, hangi erişimin izin verildiğini veya reddedildiğini belirtir ve bu kuralların alt öğelere nasıl uygulandığını (miras) belirler. İki ana ACE türü vardır:

- **Genel ACE'ler**: Bunlar genel olarak uygulanır, ya tüm nesne türlerini etkiler ya da yalnızca konteynerlar (klasörler gibi) ile konteyner olmayanlar (dosyalar gibi) arasında ayrım yapar. Örneğin, bir klasörün içeriğini görmelerine izin veren ancak içindeki dosyalara erişmelerine izin vermeyen bir kural.

- **Nesne Özel ACE'ler**: Bunlar daha kesin kontrol sağlar, belirli nesne türleri veya hatta bir nesnenin içindeki bireysel özellikler için kuralların belirlenmesine izin verir. Örneğin, bir kullanıcı dizininde, bir kullanıcının telefon numarasını güncellemesine izin veren ancak oturum açma saatlerini güncellemesine izin vermeyen bir kural olabilir.

Her ACE, kuralın kimin için geçerli olduğu (Bir Güvenlik Tanımlayıcısı veya SID kullanarak), kuralın neyi izin verdiği veya reddettiği (Erişim Maskesi kullanarak) ve diğer nesnelere nasıl miras alındığı gibi önemli bilgiler içerir.

#### ACE Türleri Arasındaki Temel Farklar

- **Genel ACE'ler**, tüm nesne yönlerine veya bir konteyner içindeki tüm nesnelere aynı kuralın uygulandığı basit erişim kontrol senaryoları için uygundur.

- **Nesne Özel ACE'ler**, özellikle Active Directory gibi ortamlarda kullanılan daha karmaşık senaryolar için kullanılır, burada belirli bir nesnenin özelliklerine farklı şekillerde erişimi kontrol etmeniz gerekebilir.

Özetlemek gerekirse, ACL'ler ve ACE'ler, hassas bilgilere veya kaynaklara sadece doğru kişilerin veya grupların erişimine izin veren, erişim haklarını bireysel özellikler veya nesne türleri düzeyine kadar özelleştirebilen kesin erişim kontrollerini tanımlamaya yardımcı olur.

### Erişim Kontrol Girişi Düzeni

| ACE Alanı   | Açıklama                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tür         | ACE'nin türünü gösteren bir bayrak. Windows 2000 ve Windows Server 2003, tüm güvenlik sağlanabilir nesnelere eklenen üç genel ACE türünü ve Active Directory nesneleri için ortaya çıkabilen üç nesne özel ACE türünü destekler.                                                                                                                                                                                                                                                            |
| Bayraklar   | Miras alma ve denetim için kontrol eden bir dizi bit bayrağı.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Boyut       | ACE için ayrılan bellekteki bayt sayısı.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Erişim maskesi | Nesnenin erişim haklarına karşılık gelen bitlere sahip 32 bitlik bir değer. Bitler açık veya kapalı olarak ayarlanabilir, ancak ayarın anlamı ACE türüne bağlıdır. Örneğin, okuma izni hakkına karşılık gelen bit açık durumdaysa ve ACE türü Reddetme ise, ACE nesnenin izinlerini okuma hakkını reddeder. Aynı bit açık durumda olsa bile ACE türü İzin ise, ACE nesnenin izinlerini okuma hakkını verir. Erişim maskesinin daha fazla ayrıntısı bir sonraki tabloda bulunur. |
| SID         | Bu ACE tarafından kontrol edilen bir kullanıcıyı veya grubu tanımlar.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Erişim Maskesi Düzeni

| Bit (Aralık) | Anlamı                            | Açıklama/Örnek                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Nesne Özel Erişim Hakları      | Veri okuma, Çalıştırma, Veri ekleme           |
| 16 - 22     | Standart Erişim Hakları             | Silme, ACL yazma, Sahip yazma            |
| 23          | Güvenlik ACL'sine erişebilir            |                                           |
| 24 - 27     | Rezerve edilmiş                           |                                           |
| 28          | Genel TÜMÜ (Okuma, Yazma, Çalıştırma) | Her şey aşağıda                          |
| 29          | Genel Çalıştırma                    | Bir programı çalıştırmak için gereken her şey |
| 30          | Genel Yazma                      | Bir dosyaya yazmak için gereken her şey   |
| 31          | Genel Okuma                       | Bir dosyayı okumak için gereken her şey       |

## Kaynaklar

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirk
