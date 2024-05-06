# ACL'ler - DACL'ler/SACL'ler/ACE'ler

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) kullanarak dünyanın **en gelişmiş** topluluk araçları tarafından desteklenen **iş akışlarını otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

<details>

<summary><strong>Sıfırdan kahramana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR'lar gönderin.

</details>

## **Erişim Kontrol Listesi (ACL)**

Bir Erişim Kontrol Listesi (ACL), bir nesne ve özellikleri için korumaları belirleyen bir dizi Sıralı Erişim Denetim Girişi (ACE) içerir. Temelde, bir ACL, belirli bir nesne üzerinde hangi eylemlerin hangi güvenlik prensipleri (kullanıcılar veya gruplar) tarafından izin verildiğini veya reddedildiğini tanımlar.

İki tür ACL vardır:

* **İsteğe Bağlı Erişim Kontrol Listesi (DACL):** Bir nesneye kimlerin erişimi olduğunu veya olmadığını belirler.
* **Sistem Erişim Kontrol Listesi (SACL):** Bir nesneye erişim denemelerinin denetimini yönetir.

Bir dosyaya erişme süreci, sistem tarafından nesnenin güvenlik tanımının kullanıcının erişim belirteciyle karşılaştırılmasıyla gerçekleşir ve erişimin, ACE'lere dayanarak hangi erişimlerin ve ne ölçüde erişimin sağlanacağı belirlenir.

### **Ana Bileşenler**

* **DACL:** Bir nesne için kullanıcılara ve gruplara erişim izinlerini veren veya reddeden ACE'leri içerir. Temelde erişim haklarını belirleyen ana ACL'dir.
* **SACL:** Nesnelere erişimi denetlemek için kullanılır, burada ACE'lerin Güvenlik Olay Günlüğü'ne kaydedilecek erişim türlerini tanımlar. Bu, yetkisiz erişim girişimlerini tespit etmek veya erişim sorunlarını gidermek için çok değerli olabilir.

### **Sistemin ACL'lerle Etkileşimi**

Her kullanıcı oturumu, o oturumla ilgili kullanıcı, grup kimlikleri ve ayrıcalıklar da dahil olmak üzere güvenlik bilgilerini içeren bir erişim belirtecine sahiptir. Bu belirteç ayrıca oturumu benzersiz şekilde tanımlayan bir oturum SID'sini içerir.

Yerel Güvenlik Otoritesi (LSASS), erişim taleplerini işleyerek, erişim denemelerinde bulunan güvenlik prensibine uyan ACE'leri inceleyerek nesnelere erişim sağlar. İlgili ACE'ler bulunamazsa erişim hemen sağlanır. Aksi takdirde, LSASS, ACE'leri erişim uygunluğunu belirlemek için erişim belirtecindeki güvenlik prensibinin SID'sini karşılaştırır.

### **Özetlenmiş Süreç**

* **ACL'ler:** DACL'ler aracılığıyla erişim izinlerini ve SACL'ler aracılığıyla denetim kurallarını tanımlar.
* **Erişim Belirteci:** Bir oturum için kullanıcı, grup ve ayrıcalık bilgilerini içerir.
* **Erişim Kararı:** DACL ACE'leri erişim belirteciyle karşılaştırılarak alınır; denetim için SACL'ler kullanılır.

### ACE'ler

**Üç ana Erişim Kontrol Girişi (ACE)** türü vardır:

* **Erişim Reddedilen ACE:** Bu ACE, belirli kullanıcılar veya gruplar için bir nesneye erişimi açıkça reddeder (bir DACL'de).
* **Erişime İzin Verilen ACE:** Bu ACE, belirli kullanıcılar veya gruplar için bir nesneye erişimi açıkça sağlar (bir DACL'de).
* **Sistem Denetim ACE'si:** Bir Sistem Erişim Kontrol Listesi (SACL) içinde konumlandırılan bu ACE, bir nesneye erişim denemeleri sırasında kullanıcılar veya gruplar tarafından denetim günlükleri oluşturur. Erişimin izin verilip verilmediğini ve erişimin doğasını belgeler.

Her ACE'nin **dört temel bileşeni** vardır:

1. Kullanıcının veya grubun **Güvenlik Tanımlayıcısı (SID)** (veya grafiksel bir temsilindeki ana adı).
2. ACE türünü tanımlayan bir **bayrak**.
3. Ebeveynlerinden ACE'yi miras alıp alamayacağını belirleyen **miras bayrakları**.
4. Nesnenin verilen haklarını belirleyen bir [**erişim maskesi**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), nesnenin verilen haklarını belirleyen 32 bitlik bir değer.

Erişim belirleme, her ACE'yi sıralı olarak inceleyerek gerçekleştirilir:

* Bir **Erişim Reddedilen ACE**, erişim belirtecinde belirtilen bir güvenilir kişiye istenen hakları açıkça reddeder.
* **Erişime İzin Verilen ACE'ler**, erişim belirtecinde belirtilen bir güvenilir kişiye tüm istenen hakları açıkça verir.
* Tüm ACE'ler kontrol edildikten sonra, herhangi bir istenen hak **açıkça izin verilmemişse**, erişim **örtük olarak reddedilir**.

### ACE'lerin Sırası

**ACE'lerin** (kimin neye erişebileceğini veya erişemeyeceğini söyleyen kurallar) **DACL** adlı listede nasıl yerleştirildiği çok önemlidir. Çünkü sistem bu kurallara dayalı olarak erişimi verir veya reddederken, geri kalanına bakmayı durdurur.

Bu ACE'leri düzenlemenin en iyi yolu vardır ve buna **"kanonik sıra"** denir. Bu yöntem, her şeyin sorunsuz ve adil çalışmasını sağlamaya yardımcı olur. İşte **Windows 2000** ve **Windows Server 2003** gibi sistemler için nasıl yapılacağı:

* İlk olarak, **bu öğe için özel olarak oluşturulan tüm kuralları** diğerlerinden önce yerleştirin, örneğin bir üst klasörden gelenler gibi.
* Bu özel kurallar arasında, **"hayır" (reddet)** olanları **"evet" (izin ver)** olanlardan önce yerleştirin.
* Başka bir yerden gelen kurallar için, en yakın kaynaktan başlayın, ardından geriye doğru gidin. Yine, **"hayır"** önce **"evet"** sonra.

Bu düzenleme iki büyük şekilde yardımcı olur:

* Belirli bir **"hayır"** olduğundan emin olur, diğer **"evet"** kuralları ne olursa olsun saygı duyulur.
* Bir dosyanın veya klasörün sahibinin, üst klasörlerden veya daha geriden gelen kurallar devreye girmeden önce kimin içeri gireceğine **son kararı** vermesine izin verir.

Bu şekilde yaparak, bir dosyanın veya klasörün sahibi, kimin erişimine izin verileceği konusunda çok hassas olabilir, doğru kişilerin içeri girebileceğinden ve yanlış kişilerin giremeyeceğinden emin olabilir.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Bu **"kanonik sıra"**, erişim kurallarının açık ve düzgün çalışmasını sağlamak, özel kuralları önce yerleştirmek ve her şeyi akıllıca düzenlemekle ilgilidir.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçları tarafından desteklenen **iş akışlarını otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### GUI Örneği

[**Buradan örnek**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/) 

Bu, bir klasörün ACL, DACL ve ACE'lerini gösteren klasik güvenlik sekmesidir:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

**Gelişmiş** düğmesine tıklarsak, miras gibi daha fazla seçenek alırız:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Ve bir Güvenlik İlkesi ekler veya düzenlersek:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Ve son olarak, Denetim sekmesinde SACL'ye sahibiz:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Erişim Kontrolünü Basitleştirilmiş Bir Şekilde Açıklama

Kaynaklara, örneğin bir klasöre erişimi yönetirken, Erişim Kontrol Listeleri (ACL'ler) ve Erişim Kontrol Girişleri (ACE'ler) olarak bilinen listeler ve kurallar kullanırız. Bu kurallar kimin belirli verilere erişebileceğini veya erişemeyeceğini tanımlar.

#### Belirli Bir Gruba Erişimi Reddetme

Maliyet adında bir klasörünüz olduğunu ve herkesin erişmesini istediğinizi ancak pazarlama ekibinin erişimini istemediğinizi hayal edin. Kuralları doğru bir şekilde ayarlayarak, pazarlama ekibinin erişimine izin vermeden herkesin erişimini sağlayabiliriz. Bu, pazarlama ekibine erişimi reddetmek için herkesin erişimine izin veren kuralın önüne pazarlama ekibine erişimi reddeden kuralın yerleştirilmesiyle yapılır.

#### Reddedilen Bir Grubun Belirli Bir Üyesine Erişime İzin Verme

Genelde pazarlama ekibinin erişimi olmamalı olsa da, pazarlama direktörü Bob'un Maliyet klasörüne erişime ihtiyacı olduğunu varsayalım. Bob için erişim sağlayan belirli bir kural (ACE) ekleyebilir ve bu kuralı pazarlama ekibine erişimi reddeden kuralın önüne yerleştirebiliriz. Böylece Bob, ekibinin genel kısıtlamasına rağmen erişim elde eder.

#### Erişim Kontrol Girişlerini Anlama

ACE'ler, bir ACL içindeki bireysel kurallardır. Kullanıcıları veya grupları tanımlar, hangi erişimin izin verildiğini veya reddedildiğini belirler ve bu kuralların alt öğelere (miras) nasıl uygulandığını belirler. İki ana ACE türü vardır:

* **Genel ACE'ler**: Geniş kapsamlı uygulanır, tüm nesne türlerini etkiler veya yalnızca konteynerler (klasörler gibi) ile konteyner olmayanlar (dosyalar gibi) arasında ayrım yapar. Örneğin, bir kuralın kullanıcılara bir klasörün içeriğini görmelerine ancak içindeki dosyalara erişmemelerine izin verdiği durum.
* **Nesne Özgü ACE'ler**: Daha kesin kontrol sağlar, belirli nesne türleri veya hatta bir nesne içindeki bireysel özellikler için kuralların belirlenmesine izin verir. Örneğin, bir kullanıcının telefon numarasını güncellemesine ancak giriş saatlerini güncellemesine izin veren bir klasörde bir kural olabilir.

Her ACE, kuralın kimin üzerinde uygulandığı (Bir Güvenlik Tanımlayıcı veya SID kullanarak), kuralın neyi izin verdiği veya reddettiği (bir erişim maskesi kullanarak) ve diğer nesneler tarafından nasıl miras alındığı gibi önemli bilgiler içerir.

#### ACE Türleri Arasındaki Temel Farklar

* **Genel ACE'ler**, aynı kuralın bir nesnenin tüm yönlerine veya bir konteyner içindeki tüm nesnelere uygulandığı basit erişim kontrol senaryoları için uygundur.
* **Nesne Özgü ACE'ler**, özellikle Active Directory gibi ortamlarda belirli bir nesnenin özelliklerine farklı şekilde erişimi kontrol etmeniz gereken karmaşık senaryolar için kullanılır.

Özetle, ACL'ler ve ACE'ler, hassas bilgilere veya kaynaklara sadece doğru kişilerin veya grupların erişimine izin vererek, erişim haklarını bireysel özellikler veya nesne türleri seviyesine kadar özelleştirebilme yeteneği sağlar.

### Erişim Kontrol Girişi Düzeni

| ACE Alanı   | Açıklama                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tür        | ACE'nin türünü gösteren bayrak. Windows 2000 ve Windows Server 2003, altı türde ACE'yi destekler: Tüm güvenli nesnelerle ilişkilendirilen üç genel ACE türü. Active Directory nesneleri için oluşabilecek üç nesne özgü ACE türü.                                                                                                                                                                                                                                                            |
| Bayraklar       | Miras ve denetimleri kontrol eden bit bayrakları kümesi.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Boyut        | ACE için ayrılan bellek baytlarının sayısı.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Erişim maskesi | Nesne için erişim haklarını belirten 32 bitlik değer. Bitler açık veya kapalı olabilir, ancak ayarın anlamı ACE türüne bağlıdır. Örneğin, okuma izinlerine karşılık gelen bit açıksa ve ACE türü Reddetme ise, ACE nesnenin izinlerini okuma hakkını reddeder. Aynı bit açıkken ve ACE türü İzin ise, ACE nesnenin izinlerini okuma hakkını verir. Erişim maskesinin ayrıntıları bir sonraki tabloda görünmektedir. |
| SID         | Bu ACE tarafından denetlenen veya izlenen bir kullanıcıyı veya grubu tanımlar.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Erişim Maskesi Düzeni

| Bit (Aralık) | Anlam                            | Açıklama/Örnek                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Nesne Özgü Erişim Hakları      | Veri okuma, Yürütme, Veri ekleme           |
| 16 - 22     | Standart Erişim Hakları             | Silme, ACL Yazma, Sahibi Yazma            |
| 23          | Güvenlik ACL'sine erişebilir            |                                           |
| 24 - 27     | Ayrılmış                           |                                           |
| 28          | Genel TÜMÜ (Okuma, Yazma, Yürütme) | Her şey aşağıda                          |
| 29          | Genel Yürütme                    | Bir programı yürütmek için gerekli olan her şey |
| 30          | Genel Yazma                      | Bir dosyaya yazmak için gerekli olan her şey   |
| 31          | Genel Okuma                       | Bir dosyayı okumak için gerekli olan her şey       |

## Referanslar

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.** takip edin.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
