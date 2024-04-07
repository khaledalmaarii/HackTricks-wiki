# ACL'ler - DACL'ler/SACL'ler/ACE'ler

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçları tarafından desteklenen **iş akışlarını otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Sıfırdan kahramana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar gönderin.

</details>

## **Erişim Kontrol Listesi (ACL)**

Erişim Kontrol Listesi (ACL), bir nesne ve özellikleri için korumaları belirleyen sıralı bir Erişim Kontrol Girişleri (ACE'ler) kümesinden oluşur. Temelde, bir ACL, belirli bir nesne üzerinde hangi güvenlik prensiplerinin (kullanıcılar veya gruplar) hangi eylemleri yapmasına izin verildiğini veya engellendiğini tanımlar.

İki tür ACL vardır:

* **İsteğe Bağlı Erişim Kontrol Listesi (DACL):** Bir nesneye kimlerin erişiminin olduğunu veya olmadığını belirler.
* **Sistem Erişim Kontrol Listesi (SACL):** Bir nesneye erişim denemelerinin denetimini yönetir.

Bir dosyaya erişme işlemi, sistem tarafından nesnenin güvenlik tanımının kullanıcının erişim belirteciyle karşılaştırılmasıyla gerçekleşir ve erişimin, ACE'ler temelinde hangi ölçüde ve kimin tarafından sağlanacağı belirlenir.

### **Ana Bileşenler**

* **DACL:** Bir nesne için kullanıcılara ve gruplara erişim izinlerini veren veya reddeden ACE'leri içerir. Temelde erişim haklarını belirleyen ana ACL'dir.
* **SACL:** Nesnelere erişimi denetlemek için kullanılır, burada ACE'lerin Güvenlik Olay Günlüğü'ne kaydedilecek erişim türlerini tanımlar. Bu, yetkisiz erişim girişimlerini tespit etmek veya erişim sorunlarını gidermek için çok değerli olabilir.

### **Sistem ACL'leri ile Etkileşim**

Her kullanıcı oturumu, o oturumla ilgili kullanıcı, grup kimlikleri ve ayrıcalıklar gibi güvenlik bilgilerini içeren bir erişim belirtecine sahiptir. Bu belirteç aynı zamanda oturumu benzersiz şekilde tanımlayan bir oturum SID'sini de içerir.

Yerel Güvenlik Otoritesi (LSASS), erişim taleplerini işleyerek, erişim denemesinde bulunan güvenlik prensibine uyan ACE'leri inceleyerek nesnelere erişim sağlar. İlgili ACE'ler bulunamazsa erişim hemen sağlanır. Aksi takdirde, LSASS, erişim uygunluğunu belirlemek için ACE'leri erişim belirtecindeki güvenlik prensibinin SID'si ile karşılaştırır.

### **Özetlenmiş Süreç**

* **ACL'ler:** DACL'ler aracılığıyla erişim izinlerini ve SACL'ler aracılığıyla denetim kurallarını tanımlar.
* **Erişim Belirteci:** Bir oturum için kullanıcı, grup ve ayrıcalık bilgilerini içerir.
* **Erişim Kararı:** DACL ACE'leri erişim belirteciyle karşılaştırılarak alınır; denetim için SACL'ler kullanılır.

### ACE'ler

**Üç ana türde Erişim Kontrol Girişleri (ACE)** vardır:

* **Erişim Reddedilen ACE:** Bu ACE, belirli kullanıcılar veya gruplar için bir nesneye erişimi açıkça reddeder (DACL'de).
* **Erişim İzin Verilen ACE:** Bu ACE, belirli kullanıcılar veya gruplar için bir nesneye erişimi açıkça sağlar (DACL'de).
* **Sistem Denetim ACE'si:** Bir Sistem Erişim Kontrol Listesi (SACL) içinde konumlandırılan bu ACE, kullanıcıların veya grupların bir nesneye erişim denemesi üzerine denetim günlükleri oluşturur. Erişimin izin verilip verilmediğini ve erişimin doğasını belgeler.

Her ACE'nin **dört temel bileşeni** vardır:

1. Kullanıcının veya grubun **Güvenlik Tanımlayıcısı (SID)** (veya grafiksel bir temsilindeki ana adı).
2. ACE türünü tanımlayan bir **bayrak**.
3. Ebeveynlerinden ACE'yi miras alıp almayacağını belirleyen **miras bayrakları**.
4. Nesnenin verilen haklarını belirleyen bir [**erişim maskesi**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), nesnenin verilen haklarını belirleyen 32 bitlik bir değer.

Erişim belirleme, her ACE'yi sıralı olarak inceleyerek yapılır:

* Bir **Erişim Reddedilen ACE**, erişim belirtecinde belirtilen vekile belirli hakları açıkça reddeder.
* **Erişim İzin Verilen ACE'ler**, erişim belirtecinde belirtilen vekile tüm istenen hakları açıkça sağlar.
* Tüm ACE'ler kontrol edildikten sonra, istenen herhangi bir hak **açıkça izin verilmemişse**, erişim **örtük olarak reddedilir**.

### ACE'lerin Sırası

**ACE'lerin** (kimin neye erişebileceğini veya erişemeyeceğini söyleyen kurallar) **DACL** adlı listede nasıl yerleştirildiği çok önemlidir. Çünkü sistem bu kurallara dayanarak erişimi verir veya reddederken, geri kalanına bakmayı durdurur.

Bu ACE'leri düzenlemenin en iyi yolu vardır ve buna **"kanonik sıra"** denir. Bu yöntem, her şeyin sorunsuz ve adil çalışmasını sağlamaya yardımcı olur. İşte **Windows 2000** ve **Windows Server 2003** gibi sistemler için nasıl yapılacağı:

* İlk olarak, **bu öğe için özel olarak oluşturulan tüm kuralları** diğerlerinden önce yerleştirin, örneğin bir üst klasörden gelenler gibi.
* Bu özel kurallar içinde, **"hayır" (reddet)** diyenleri **"evet" (izin ver)** diyenlerden önce yerleştirin.
* Başka bir yerden gelen kurallar için, en yakın kaynaktan, yani üst klasörden başlayın ve oradan geriye gidin. Yine, **"hayır"** önce **"evet"** diyin.

Bu düzenleme iki büyük şekilde yardımcı olur:

* Özel bir **"hayır"** olduğundan emin olur, diğer **"evet"** kuralları ne olursa olsun, saygı duyulur.
* Bir dosyanın veya klasörün sahibinin, üst klasörlerden veya daha geriden gelen kurallar devreye girmeden önce kimin içeri gireceğine **son kararı** vermesine izin verir.

Bu şekilde yaparak, bir dosya veya klasör sahibi, kimin erişim sağlayabileceğinden emin olabilir, doğru kişilerin içeri girebileceğinden ve yanlış olanların giremeyeceğinden emin olabilir.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Bu **"kanonik sıra"**, erişim kurallarının açık ve düzgün çalışmasını sağlamak, özel kuralları öne çıkarmak ve her şeyi akıllıca düzenlemekle ilgilidir.

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçları tarafından desteklenen **iş akışlarını otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### GUI Örneği

[**Buradan örnek**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/) alınmıştır.

Bu, bir klasörün klasik güvenlik sekmesini gösteren ACL, DACL ve ACE'leri gösteren bir örnektir:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

**Gelişmiş** düğmesine tıklarsak, miras gibi daha fazla seçenek alırız:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Ve bir Güvenlik İlkesi ekler veya düzenlersek:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Ve son olarak, Denetim sekmesindeki SACL'ye sahibiz:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Erişim Kontrolünü Basitleştirilmiş Bir Şekilde Açıklama

Kaynaklara, örneğin bir klasöre erişimi yönetirken, Erişim Kontrol Listeleri (ACL'ler) ve Erişim Kontrol Girişleri (ACE'ler) olarak bilinen listeler ve kurallar kullanırız. Bu, belirli verilere kimin erişebileceğini veya erişemeyeceğini tanımlar.

#### Belirli Bir Gruba Erişimi Reddetme

Maliyet adında bir klasörünüz olduğunu ve herkesin erişmesini istediğinizi ancak pazarlama ekibinin erişimini istemediğinizi hayal edin. Kuralları doğru bir şekilde ayarlayarak, pazarlama ekibinin erişimini herkesin erişimine izin vermeden önce açıkça reddedebiliriz. Bu, pazarlama ekibine erişimi reddeden kuralı, herkese erişime izin veren kuralın önüne yerleştirerek yapılır.

#### Reddedilen Bir Grubun Belirli Bir Üyesine Erişime İzin Verme

Genelde pazarlama ekibinin erişimi olmamalı olsa da, pazarlama direktörü Bob'un Maliyet klasörüne erişime ihtiyacı olduğunu varsayalım. Bob için erişim sağlayan belirli bir kural (ACE) ekleyebilir ve bu kuralı pazarlama ekibine erişimi reddeden kuralın önüne yerleştirebiliriz. Böylece Bob, ekibinin genel kısıtlamasına rağmen erişim elde eder.

#### Erişim Kontrol Girişlerini Anlama

ACE'ler, bir ACL içindeki bireysel kurallardır. Kullanıcıları veya grupları tanımlar, hangi erişimin izin verildiğini veya reddedildiğini belirtir ve bu kuralların alt öğelere (miras) nasıl uygulandığını belirler. İki ana ACE türü vardır:

* **Genel ACE'ler**: Bu geniş kapsamlıdır, tüm nesneleri etkiler veya yalnızca konteynerler (klasörler gibi) ile konteyner olmayanlar (dosyalar gibi) arasında ayrım yapar. Örneğin, bir kuralın kullanıcılara bir klasörün içeriğini görmelerine ancak içindeki dosyalara erişmemelerine izin verdiği bir kural.
* **Nesne Özgü ACE'ler**: Bu, daha kesin kontrol sağlar, belirli nesne türleri veya hatta bir nesne içindeki bireysel özellikler için kuralların belirlenmesine izin verir. Örneğin, bir kullanıcının telefon numarasını güncellemesine ancak giriş saatlerini güncellememesine izin veren bir kural olabilir.

Her ACE, kuralın kimin için geçerli olduğu (Bir Güvenlik Kimliği veya SID kullanarak), kuralın neyi izin verdiği veya reddettiği (erişim maskesi kullanarak) ve diğer nesneler tarafından nasıl miras alındığı gibi önemli bilgiler içerir.

#### ACE Türleri Arasındaki Temel Farklar

* **Genel ACE'ler**, aynı kuralın bir nesnenin tüm yönlerine veya bir konteyner içindeki tüm nesnelere uygulandığı basit erişim kontrol senaryoları için uygundur.
* **Nesne Özgü ACE'ler**, özellikle Active Directory gibi ortamlarda, nesnenin belirli özelliklerine farklı erişim kontrolü sağlamanız gereken karmaşık senaryolarda kullanılır.

Özetle, ACL'ler ve ACE'ler, hassas bilgilere veya kaynaklara sadece doğru bireylerin veya grupların erişimine izin vererek, erişim haklarını bireysel özellikler veya nesne türleri seviyesine kadar özelleştirmenize yardımcı olur.

### Erişim Kontrol Girişi Düzeni

| ACE Alanı   | Açıklama                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tür        | ACE'nin türünü gösteren bayrak. Windows 2000 ve Windows Server 2003, altı türde ACE'yi destekler: Tüm güvenli nesnelerle ilişkilendirilen üç genel ACE türü. Active Directory nesneleri için oluşabilecek üç nesne özgü ACE türü.                                                                                                                                                                                                                                                            |
| Bayraklar       | Miras ve denetimleri kontrol eden bir dizi bit bayrağı.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Boyut        | ACE için ayrılan bellekteki bayt sayısı.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Erişim maskesi | Nesne için erişim haklarına karşılık gelen 32 bitlik değer. Bitler açık veya kapalı olabilir, ancak ayarın anlamı ACE türüne bağlıdır. Örneğin, okuma izinlerine karşılık gelen bit açıksa ve ACE türü Reddetme ise, ACE nesnenin izinlerini okuma hakkını reddeder. Aynı bit açıksa ancak ACE türü İzin ise, ACE nesnenin izinlerini okuma hakkını verir. Erişim maskesinin ayrıntıları bir sonraki tabloda görünmektedir. |
| SID         | Bu ACE tarafından kontrol edilen veya izlenen bir kullanıcıyı veya grubu tanımlar.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Erişim Maskesi Düzeni

| Bit (Aralık) | Anlam                            | Açıklama/Örnek                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Nesne Özgü Erişim Hakları      | Veri okuma, Yürütme, Veri ekleme           |
| 16 - 22     | Standart Erişim Hakları             | Silme, ACL yazma, Sahip yazma            |
| 23          | Güvenlik ACL'sine erişebilir            |                                           |
| 24 - 27     | Ayrılmış                           |                                           |
| 28          | Genel TÜMÜ (Okuma, Yazma, Yürütme) | Aşağıdaki her şey                          |
| 29          | Genel Yürütme                    | Bir programı çalıştırmak için gerekli olan her şey |
| 30          | Genel Yazma                      | Bir dosyaya yazmak için gereken her şey   |
| 31          | Genel Okuma                       | Bir dosyayı okumak için gereken her şey       |

## Referanslar

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)
