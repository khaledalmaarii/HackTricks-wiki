# macOS Dirty NIB

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Tekniğin detayları için orijinal gönderiyi kontrol edin: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** İşte bir özet:

NIB dosyaları, Apple'ın geliştirme ekosisteminin bir parçası olarak, uygulamalardaki **UI öğelerini** ve etkileşimlerini tanımlamak için tasarlanmıştır. Pencereler ve düğmeler gibi serileştirilmiş nesneleri kapsar ve çalışma zamanında yüklenir. Sürekli kullanımlarına rağmen, Apple artık daha kapsamlı UI akış görselleştirmesi için Storyboard'ları önermektedir.

### NIB Dosyaları ile İlgili Güvenlik Endişeleri
**NIB dosyalarının bir güvenlik riski olabileceğini** belirtmek önemlidir. **Rastgele komutlar çalıştırma** potansiyeline sahiptirler ve bir uygulama içindeki NIB dosyalarındaki değişiklikler, Gatekeeper'ın uygulamayı çalıştırmasını engellemez, bu da önemli bir tehdit oluşturur.

### Dirty NIB Enjeksiyon Süreci
#### NIB Dosyası Oluşturma ve Ayarlama
1. **İlk Kurulum**:
- XCode kullanarak yeni bir NIB dosyası oluşturun.
- Arayüze bir Nesne ekleyin, sınıfını `NSAppleScript` olarak ayarlayın.
- Kullanıcı Tanımlı Çalışma Zamanı Özellikleri aracılığıyla ilk `source` özelliğini yapılandırın.

2. **Kod Çalıştırma Aleti**:
- Kurulum, AppleScript'in talep üzerine çalıştırılmasını sağlar.
- `Apple Script` nesnesini etkinleştirmek için bir düğme ekleyin, özellikle `executeAndReturnError:` seçicisini tetikleyin.

3. **Test Etme**:
- Test amaçlı basit bir Apple Script:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- XCode hata ayıklayıcısında çalıştırarak ve düğmeye tıklayarak test edin.

#### Bir Uygulamayı Hedefleme (Örnek: Pages)
1. **Hazırlık**:
- Hedef uygulamayı (örneğin, Pages) ayrı bir dizine (örneğin, `/tmp/`) kopyalayın.
- Gatekeeper sorunlarını aşmak ve önbelleğe almak için uygulamayı başlatın.

2. **NIB Dosyasını Üzerine Yazma**:
- Mevcut bir NIB dosyasını (örneğin, Hakkında Panel NIB) oluşturulan DirtyNIB dosyasıyla değiştirin.

3. **Çalıştırma**:
- Uygulama ile etkileşimde bulunarak çalıştırmayı tetikleyin (örneğin, `Hakkında` menü öğesini seçerek).

#### Kavramsal Kanıt: Kullanıcı Verilerine Erişim
- Kullanıcı izni olmadan fotoğraflar gibi kullanıcı verilerine erişmek ve çıkarmak için AppleScript'i değiştirin.

### Kod Örneği: Kötü Amaçlı .xib Dosyası
- Rastgele kod çalıştırmayı gösteren bir [**kötü amaçlı .xib dosyası örneği**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) erişin ve inceleyin.

### Başlatma Kısıtlamalarını Ele Alma
- Başlatma Kısıtlamaları, uygulama çalıştırmayı beklenmedik yerlerden (örneğin, `/tmp`) engeller.
- Başlatma Kısıtlamaları ile korunmayan uygulamaları tanımlamak ve NIB dosyası enjeksiyonu için hedeflemek mümkündür.

### Ek macOS Koruma Önlemleri
macOS Sonoma'dan itibaren, Uygulama paketleri içindeki değişiklikler kısıtlanmıştır. Ancak, önceki yöntemler şunları içeriyordu:
1. Uygulamayı farklı bir konuma (örneğin, `/tmp/`) kopyalamak.
2. İlk korumaları aşmak için uygulama paketindeki dizinleri yeniden adlandırmak.
3. Uygulamayı çalıştırarak Gatekeeper ile kaydolduktan sonra, uygulama paketini değiştirmek (örneğin, MainMenu.nib'i Dirty.nib ile değiştirmek).
4. Dizinleri geri yeniden adlandırmak ve enjeksiyon yapılan NIB dosyasını çalıştırmak için uygulamayı yeniden çalıştırmak.

**Not**: Son macOS güncellemeleri, Gatekeeper önbelleklemesinden sonra uygulama paketleri içinde dosya değişikliklerini engelleyerek bu istismarı etkisiz hale getirmiştir.
