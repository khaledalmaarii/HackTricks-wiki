# macOS Anahtarlık

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **tehlikeye atılıp atılmadığını** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## Anahtarlık Anahtarları

* **Kullanıcı Anahtarlığı** (`~/Library/Keychains/login.keycahin-db`), uygulama şifreleri, internet şifreleri, kullanıcı tarafından oluşturulan sertifikalar, ağ şifreleri ve kullanıcı tarafından oluşturulan genel/özel anahtarlar gibi **kullanıcıya özgü kimlik bilgilerini** saklamak için kullanılır.
* **Sistem Anahtarlığı** (`/Library/Keychains/System.keychain`), WiFi şifreleri, sistem kök sertifikaları, sistem özel anahtarları ve sistem uygulama şifreleri gibi **sistem genelindeki kimlik bilgilerini** saklar.

### Şifre Anahtarlığı Erişimi

Bu dosyalar, doğal korumaya sahip olmasalar da **indirilebilirler** ve şifreli oldukları için **kullanıcının düz metin şifresine ihtiyaç duyarlar**. [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir araç şifre çözme işlemi için kullanılabilir.

## Anahtarlık Girişleri Korumaları

### ACL'ler

Anahtarlıkta her giriş, anahtarlık girişinde çeşitli işlemleri kimin yapabileceğini belirleyen **Erişim Kontrol Listeleri (ACL'ler)** tarafından yönetilir, bunlar şunları içerir:

* **ACLAuhtorizationExportClear**: Sahibin sırrın açık metnini almasına izin verir.
* **ACLAuhtorizationExportWrapped**: Sahibin sırrı başka bir sağlanan şifre ile şifrelenmiş açık metin olarak almasına izin verir.
* **ACLAuhtorizationAny**: Sahibin herhangi bir işlemi gerçekleştirmesine izin verir.

ACL'ler, bu işlemleri kullanıcıya sormadan gerçekleştirebilen **güvenilir uygulamaların listesi** ile desteklenir. Bu şunları içerebilir:

* **N`il`** (izin gerekmez, **herkes güvenilir**)
* Boş bir liste (**hiç kimse güvenilir değil**)
* Belirli **uygulamaların** listesi.

Ayrıca giriş, **`ACLAuthorizationPartitionID`** anahtarını içerebilir, bu da **teamid, apple** ve **cdhash'yi** tanımlamak için kullanılır.

* Eğer **teamid** belirtilmişse, giriş değerine **izin vermek** için kullanılan uygulamanın **aynı teamid'ye** sahip olması gerekir.
* Eğer **apple** belirtilmişse, uygulamanın **Apple** tarafından **imzalanmış** olması gerekir.
* Eğer **cdhash** belirtilmişse, uygulamanın belirli bir **cdhash'e** sahip olması gerekir.

### Bir Anahtarlık Girişi Oluşturma

Yeni bir **giriş** **`Anahtarlık Erişimi.app`** kullanılarak oluşturulduğunda, aşağıdaki kurallar geçerlidir:

* Tüm uygulamalar şifreleyebilir.
* Hiçbir uygulama dışa aktaramaz/şifre çözemez (kullanıcıya sormadan).
* Tüm uygulamalar bütünlük kontrolünü görebilir.
* Hiçbir uygulama ACL'leri değiştiremez.
* **PartitionID** **`apple`** olarak ayarlanır.

Bir **uygulama anahtarlıkta bir giriş oluşturduğunda**, kurallar biraz farklıdır:

* Tüm uygulamalar şifreleyebilir.
* Yalnızca **oluşturan uygulama** (veya açıkça eklenen diğer uygulamalar) dışa aktarabilir/şifre çözebilir (kullanıcıya sormadan).
* Tüm uygulamalar bütünlük kontrolünü görebilir.
* Hiçbir uygulama ACL'leri değiştiremez.
* **PartitionID** **`teamid:[buraya teamID]`** olarak ayarlanır.

## Anahtarlığa Erişim

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### API'ler

{% hint style="success" %}
**Anahtarlık numaralandırma ve sızdırmazlık** oluşturmayacak sırların **dökülmesi**, [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracı ile yapılabilir.
{% endhint %}

Her anahtarlık girişi hakkında **bilgi** listele ve al:

* **`SecItemCopyMatching`** API'si her giriş hakkında bilgi verir ve kullanırken ayarlayabileceğiniz bazı özellikler vardır:
* **`kSecReturnData`**: Doğruysa, verileri şifrelemeye çalışır (olası açılır pencereleri önlemek için false olarak ayarlayın)
* **`kSecReturnRef`**: Anahtarlık öğesine referansı da alın (daha sonra açılır pencereler olmadan şifreleyebileceğinizi gördüğünüzde true olarak ayarlayın)
* **`kSecReturnAttributes`**: Girişler hakkında meta verileri alın
* **`kSecMatchLimit`**: Kaç sonuç döndürüleceği
* **`kSecClass`**: Hangi türde anahtarlık girişi

Her girişin **ACL'leri**ni alın:

* **`SecAccessCopyACLList`** API'si ile **anahtarlık öğesi için ACL'yi** alabilir ve her liste şunları içeren bir ACL listesi döndürecektir:
* Açıklama
* **Güvenilen Uygulama Listesi**. Bu şunlar olabilir:
* Bir uygulama: /Applications/Slack.app
* Bir ikili: /usr/libexec/airportd
* Bir grup: group://AirPort

Veriyi dışa aktarın:

* **`SecKeychainItemCopyContent`** API'si düz metni alır
* **`SecItemExport`** API'si anahtarları ve sertifikaları dışa aktarır ancak içeriği şifreli olarak dışa aktarmak için şifreleri ayarlamak gerekebilir

Ve **bir açılır pencere olmadan bir sırrı dışa aktarabilmek** için gereksinimler şunlardır:

* Eğer **1'den fazla güvenilen** uygulama listelenmişse:
* Uygun **yetkilendirmelere** ihtiyaç vardır (**`Nil`**, veya sırra erişim yetkisi için yetkilendirme izin listesinde olmak)
* Kod imzasının **PartitionID** ile eşleşmesi gerekir
* Kod imzasının bir **güvenilen uygulamanın** kod imzasıyla eşleşmesi gerekir (veya doğru KeychainAccessGroup üyesi olmak)
* Eğer **tüm uygulamalar güvenilirse**:
* Uygun **yetkilendirmelere** ihtiyaç vardır
* Kod imzasının **PartitionID** ile eşleşmesi gerekir
* Eğer **PartitionID yoksa**, bu gerekli değildir

{% hint style="danger" %}
Bu nedenle, eğer **1 uygulama listelenmişse**, o uygulamaya **kod enjekte etmeniz gerekir**.

Eğer **partitionID'de apple** belirtilmişse, **`osascript`** ile erişebilirsiniz, böylece partitionID'de apple olan tüm uygulamalara güvenen herhangi bir şeye erişebilirsiniz. **`Python`** bunun için de kullanılabilir.
{% endhint %}

### İki ek özellik

* **Görünmez**: Girişi **UI** Anahtarlık uygulamasından **gizlemek** için bir boolean bayrağıdır
* **Genel**: **Meta verileri** saklamak için kullanılır (bu nedenle **ŞİFRELENMEMİŞTİR**)
* Microsoft, hassas uç noktalara erişmek için tüm yenileme tokenlarını düz metinde saklıyordu.

## Referanslar

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **tehlikeye atılıp atılmadığını** kontrol etmek için **ücretsiz** işlevsellikler sunan **karanlık ağ** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve **ücretsiz** olarak motorlarını deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS Hacking öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Sponsorluk planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* Hacking püf noktalarını göndererek HackTricks ve HackTricks Cloud github depolarına PR'lar göndererek paylaşın.

</details>
{% endhint %}
