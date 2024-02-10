# macOS Anahtar Zinciri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına **PR göndererek** hilelerinizi paylaşın.

</details>

## Ana Anahtar Zincirleri

* **Kullanıcı Anahtar Zinciri** (`~/Library/Keychains/login.keycahin-db`), uygulama şifreleri, internet şifreleri, kullanıcı tarafından oluşturulan sertifikalar, ağ şifreleri ve kullanıcı tarafından oluşturulan genel/özel anahtarlar gibi **kullanıcıya özgü kimlik bilgilerini** saklamak için kullanılır.
* **Sistem Anahtar Zinciri** (`/Library/Keychains/System.keychain`), WiFi şifreleri, sistem kök sertifikaları, sistem özel anahtarları ve sistem uygulama şifreleri gibi **sistem genelindeki kimlik bilgilerini** saklar.

### Şifre Anahtar Zinciri Erişimi

Bu dosyalar, **doğal korumaya sahip olmasalar da indirilebilir** ve **kullanıcının düz metin şifresinin şifresini çözmek** için şifrelenmiştir. Şifre çözme için [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir araç kullanılabilir.

## Anahtar Zinciri Girişleri Koruma

### ACL'ler

Anahtar zincirindeki her giriş, anahtar zinciri girişi üzerinde çeşitli işlemleri gerçekleştirebilecek kişileri belirleyen **Erişim Kontrol Listeleri (ACL'ler)** tarafından yönetilir. Bu işlemler şunları içerebilir:

* **ACLAuhtorizationExportClear**: Sahibin sırrın açık metnini almasına izin verir.
* **ACLAuhtorizationExportWrapped**: Sahibin başka bir sağlanan şifreyle şifrelenmiş açık metni almasına izin verir.
* **ACLAuhtorizationAny**: Sahibin herhangi bir işlemi gerçekleştirmesine izin verir.

ACL'ler, bu işlemleri sormadan gerçekleştirebilen **güvenilir uygulamaların bir listesiyle** birlikte gelir. Bu şunları içerebilir:

* &#x20;**N`il`** (yetkilendirme gerektirilmez, **herkes güvenilir**)
* **Boş** bir liste (**hiç kimse güvenilir değil**)
* Belirli **uygulamaların listesi**.

Ayrıca giriş, **`ACLAuthorizationPartitionID`** anahtarını içerebilir, bu da **teamid, apple** ve **cdhash'yi** tanımlamak için kullanılır.

* Eğer **teamid** belirtilmişse, giriş değerine **sorma olmadan** erişmek için kullanılan uygulamanın **aynı teamid'ye** sahip olması gerekir.
* Eğer **apple** belirtilmişse, uygulama **Apple** tarafından **imzalanmış** olmalıdır.
* Eğer **cdhash** belirtilmişse, uygulama belirli bir **cdhash'e** sahip olmalıdır.

### Bir Anahtar Zinciri Girişi Oluşturma

**`Keychain Access.app`** kullanılarak **yeni bir giriş oluşturulduğunda**, aşağıdaki kurallar geçerlidir:

* Tüm uygulamalar şifreleyebilir.
* **Hiçbir uygulama** ihracat/şifre çözme yapamaz (kullanıcıya sormadan).
* Tüm uygulamalar bütünlük kontrolünü görebilir.
* Hiçbir uygulama ACL'leri değiştiremez.
* **PartitionID** **`apple`** olarak ayarlanır.

Bir **uygulama anahtar zincirine bir giriş oluşturduğunda**, kurallar biraz farklıdır:

* Tüm uygulamalar şifreleyebilir.
* Yalnızca **oluşturan uygulama** (veya başka uygulamalar da eklenmişse) ihracat/şifre çözme yapabilir (kullanıcıya sormadan).
* Tüm uygulamalar bütünlük kontrolünü görebilir.
* Hiçbir uygulama ACL'leri değiştiremez.
* **PartitionID** **`teamid:[buraya takım kimliği]`** olarak ayarlanır.

## Anahtar Zincirine Erişim

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
**Anahtar zinciri numaralandırma ve sızıntı oluşturmayan** sırların dökümü, [**LockSmith**](https://github.com/its-a-feature/LockSmith) adlı araçla yapılabilir.
{% endhint %}

Her anahtar zinciri girişi hakkında **bilgi** alın ve listelenin:

* **`SecItemCopyMatching`** API'si her giriş hakkında bilgi verir ve kullanırken ayarlayabileceğiniz bazı özellikler vardır:
* **`kSecReturnData`**: Eğer doğruysa, verileri şifrelemeye çalışır (potansiyel açılır pencereleri önlemek için false olarak ayarlayın)
* **`kSecReturnRef`**: Anahtar zinciri öğesine referansı da alın (sonradan açılır pencereler olmadan şifrelemeyi yapabiliyorsanız true olarak ayarlayın)
* **`kSecReturnAttributes`**: Girişler hakkında meta verileri alın
* **`kSecMatchLimit`**: Kaç sonuç döndürüleceği
* **`kSecClass`**: Hangi tür anahtar zinciri girişi

Her girişin **ACL'lerini** alın:

* **`SecAccessCopyACLList`** API'siyle anahtar zinciri öğesinin **ACL'sini** alabilir ve her bir liste şunları içerir:
* Açıklama
* **Güvenilir Uygulama Listesi**. Bu bir uygulama olabilir: /Applications/Slack.app
* Bir ikili dosya olabilir: /usr/libexec/airportd
* Bir grup olabilir: group://AirPort

Veriyi dışa aktarın:

* **`SecKeychainItemCopyContent`** API'si düz metni alır
* **`SecItemExport`** API'si anahtarları ve sertifikaları dışa aktarır, ancak içeriği şifreli olarak dışa aktarmak için şifreleri ayarlamak gerekebilir

Ve sızıntı oluşturmadan bir sırrı dışa aktarabilmek için **gereksinimler** şunlardır:

* Eğer **1 veya daha fazla güvenilir** uygulama listelenmişse:
* Uygun **yetkilendirmelere** ihtiyaç vardır (**`Nil`**, veya sırra erişim yetkisi için yetkilendirme izin verilen uygulama listesinin bir parçası olmak)
* Kod imzasının **PartitionID** ile eşleşmesi gerekmektedir
* Kod imzasının **güvenilir bir uygulama** ile eşleşmesi gerekmektedir (veya doğru KeychainAccessGroup üyesi olmak)
* Eğer **tüm uygulamalar güvenilir** ise:
* Uygun **yetkilendirmelere** ihtiyaç vardır
* Kod imzasının **PartitionID** ile eşleşmesi gerekmektedir
* Eğer **PartitionID** yoksa, bu gerekli değildir

{% hint style="danger" %}
Bu nedenle, eğer **1 uygulama listelenmişse**, o uygulamaya **kod enjekte etmeniz gerekmektedir**.

Eğer **partitionID**'de **apple** belirtilmişse, **`osascript`** ile erişebilirsiniz, böylece partitionID'sinde apple olan tüm uygulamalara güvenen herhangi bir şey. Bunun için **`Python`** da kullanılabilir.
{% endhint %}

### İki ek özellik

* **Görünmez**: Bu, girişi **UI** Anahtar Zinciri uygulamasından **gizlemek** için bir boolean bayrağıdır.
* **Genel**: Bu, **meta verileri** depolamak için kullanılır (bu nedenle ŞİFRELENMEZ)
* Microsoft, hassas uç noktalara erişmek için tüm yenileme belirteçlerini düz metinde depoluyordu.

## Referanslar

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da** takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
