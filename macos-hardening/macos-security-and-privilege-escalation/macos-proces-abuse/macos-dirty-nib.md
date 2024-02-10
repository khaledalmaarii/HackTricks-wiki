# macOS Kirli NIB

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **pull request** göndererek paylaşın.

</details>

**Teknik hakkında daha fazla ayrıntı için orijinal yayına bakın: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** İşte bir özet:

NIB dosyaları, Apple'ın geliştirme ekosisteminin bir parçası olarak uygulamalardaki **UI öğelerini** ve etkileşimlerini tanımlamak için kullanılır. Pencereler ve düğmeler gibi seri nesneleri içerir ve çalışma zamanında yüklenir. Apple, NIB dosyalarının devam eden kullanımına rağmen, daha kapsamlı bir UI akış görselleştirmesi için Artık Storyboard'ları önermektedir.

### NIB Dosyalarıyla İlgili Güvenlik Endişeleri
NIB dosyalarının bir güvenlik riski olabileceğini unutmamak önemlidir. Bunlar, **keyfi komutları** yürütebilir ve bir uygulamadaki NIB dosyalarının değiştirilmesi, Gatekeeper'ın uygulamayı yürütmesini engellemez, bu da ciddi bir tehdit oluşturur.

### Kirli NIB Enjeksiyon Süreci
#### Bir NIB Dosyası Oluşturma ve Ayarlama
1. **Başlangıç Ayarları**:
- XCode kullanarak yeni bir NIB dosyası oluşturun.
- Arayüze bir Nesne ekleyin ve sınıfını `NSAppleScript` olarak ayarlayın.
- Başlangıç `source` özelliğini Kullanıcı Tanımlı Çalışma Zamanı Öznitelikleri aracılığıyla yapılandırın.

2. **Kod Yürütme Aracı**:
- Ayarlar, AppleScript'in isteğe bağlı olarak çalıştırılmasını sağlar.
- `Apple Script` nesnesini etkinleştirmek için bir düğme entegre edin ve özellikle `executeAndReturnError:` seçicisini tetikleyin.

3. **Test**:
- Test amaçlı basit bir Apple Script:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- XCode hata ayıklayıcısında çalıştırarak ve düğmeye tıklayarak test edin.

#### Bir Uygulamayı Hedefleme (Örnek: Pages)
1. **Hazelik**:
- Hedef uygulamayı (örneğin, Pages) ayrı bir dizine (örneğin, `/tmp/`) kopyalayın.
- Gatekeeper sorunlarını atlamak ve önbelleğe almak için uygulamayı başlatın.

2. **NIB Dosyasını Üzerine Yazma**:
- Varolan bir NIB dosyasını (örneğin, About Panel NIB) oluşturulan DirtyNIB dosyasıyla değiştirin.

3. **Yürütme**:
- Uygulamayla etkileşime geçerek (örneğin, `About` menü öğesini seçerek) yürütmeyi tetikleyin.

#### Kanıt: Kullanıcı Verilerine Erişim
- AppleScript'i değiştirerek, kullanıcının izni olmaksızın fotoğraflar gibi kullanıcı verilerine erişebilir ve çıkarabilirsiniz.

### Örnek Kod: Zararlı .xib Dosyası
- Keyfi kod yürütme gösteren [**zararlı bir .xib dosyasının örneğine**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) erişin ve inceleyin.

### Başlatma Kısıtlamalarıyla İlgilenme
- Başlatma Kısıtlamaları, beklenmeyen konumlardan (örneğin, `/tmp`) uygulama yürütmesini engeller.
- Başlatma Kısıtlamaları tarafından korunmayan uygulamaları belirlemek ve NIB dosyası enjeksiyonu için hedef almak mümkündür.

### Ek macOS Korumaları
macOS Sonoma'dan itibaren, App paketleri içindeki değişiklikler kısıtlanmıştır. Ancak, önceki yöntemler şunları içerir:
1. Uygulamayı farklı bir konuma (örneğin, `/tmp/`) kopyalama.
2. Uygulama paketi içindeki dizinleri yeniden adlandırarak başlangıç korumalarını atlatma.
3. Uygulamayı Gatekeeper ile kaydetmek için çalıştırdıktan sonra, uygulama paketini (örneğin, MainMenu.nib'i Dirty.nib ile değiştirme) değiştirme.
4. Dizinleri yeniden adlandırma ve enjekte edilen NIB dosyasını yürütmek için uygulamayı yeniden çalıştırma.

**Not**: Son macOS güncellemeleri, Gatekeeper önbelleğinde dosya değişikliklerini engelleyerek bu saldırıyı etkisiz hale getirmiştir.
