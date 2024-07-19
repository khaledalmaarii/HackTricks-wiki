# BloodHound & Diğer AD Enum Araçları

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) Sysinternal Suite'ten:

> Gelişmiş bir Active Directory (AD) görüntüleyici ve düzenleyici. AD Explorer'ı, bir AD veritabanında kolayca gezinmek, favori konumları tanımlamak, nesne özelliklerini ve niteliklerini diyalog kutuları açmadan görüntülemek, izinleri düzenlemek, bir nesnenin şemasını görüntülemek ve kaydedip yeniden çalıştırabileceğiniz karmaşık aramalar gerçekleştirmek için kullanabilirsiniz.

### Anlık Görüntüler

AD Explorer, AD'nin anlık görüntülerini oluşturabilir, böylece çevrimdışı kontrol edebilirsiniz.\
Çevrimdışı zafiyetleri keşfetmek veya AD DB'nin farklı durumlarını zaman içinde karşılaştırmak için kullanılabilir.

Bağlanmak için kullanıcı adı, şifre ve yönlendirme gereklidir (herhangi bir AD kullanıcısı gereklidir).

AD'nin anlık görüntüsünü almak için `File` --> `Create Snapshot` yolunu izleyin ve anlık görüntü için bir isim girin.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon), bir AD ortamından çeşitli artefaktları çıkaran ve birleştiren bir araçtır. Bilgiler, analiz kolaylığı sağlamak ve hedef AD ortamının mevcut durumu hakkında bütünsel bir resim sunmak için metriklerle birlikte özet görünümler içeren **özel formatlanmış** Microsoft Excel **raporu** şeklinde sunulabilir.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound, [Linkurious](http://linkurio.us/) üzerine inşa edilmiş, [Electron](http://electron.atom.io/) ile derlenmiş, C# veri toplayıcı tarafından beslenen bir [Neo4j](https://neo4j.com/) veritabanına sahip tek sayfa Javascript web uygulamasıdır.

BloodHound, bir Active Directory veya Azure ortamındaki gizli ve genellikle istenmeyen ilişkileri ortaya çıkarmak için grafik teorisini kullanır. Saldırganlar, BloodHound'u kullanarak, aksi takdirde hızlı bir şekilde tanımlanması imkansız olan son derece karmaşık saldırı yollarını kolayca belirleyebilirler. Savunucular, BloodHound'u kullanarak aynı saldırı yollarını tanımlayıp ortadan kaldırabilirler. Hem mavi hem de kırmızı takımlar, BloodHound'u kullanarak bir Active Directory veya Azure ortamındaki ayrıcalık ilişkilerini daha derinlemesine anlamak için kolayca faydalanabilirler.

Bu nedenle, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) otomatik olarak bir alanı listeleyebilen, tüm bilgileri kaydedebilen, olası ayrıcalık yükseltme yollarını bulabilen ve tüm bilgileri grafikler kullanarak gösterebilen harika bir araçtır.

BloodHound, 2 ana bölümden oluşur: **veri toplayıcılar** ve **görselleştirme uygulaması**.

**Veri toplayıcılar**, alanı **listelemek ve tüm bilgileri** görselleştirme uygulamasının anlayacağı bir formatta çıkarmak için kullanılır.

**Görselleştirme uygulaması, tüm bilgilerin nasıl ilişkili olduğunu göstermek ve alandaki ayrıcalıkları yükseltmenin farklı yollarını göstermek için neo4j kullanır.**

### Kurulum
BloodHound CE'nin oluşturulmasından sonra, tüm proje Docker ile kullanım kolaylığı için güncellendi. Başlamak için en kolay yol, önceden yapılandırılmış Docker Compose yapılandırmasını kullanmaktır.

1. Docker Compose'u kurun. Bu, [Docker Desktop](https://www.docker.com/products/docker-desktop/) kurulumu ile birlikte gelmelidir.
2. Çalıştırın:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Docker Compose'un terminal çıktısında rastgele oluşturulmuş şifreyi bulun.  
4. Bir tarayıcıda http://localhost:8080/ui/login adresine gidin. admin kullanıcı adı ve günlüklerden rastgele oluşturulmuş şifre ile giriş yapın.  

Bundan sonra rastgele oluşturulmuş şifreyi değiştirmeniz gerekecek ve ingestor'ları doğrudan indirebileceğiniz yeni arayüz hazır olacak.  

### SharpHound  

Birçok seçeneği var ama eğer alan adına katılmış bir PC'den SharpHound'u çalıştırmak ve mevcut kullanıcıyı kullanarak tüm bilgileri çıkarmak istiyorsanız:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod** ve döngü oturumu hakkında daha fazla bilgi için [buraya](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained) göz atabilirsiniz.

Farklı kimlik bilgileri kullanarak SharpHound'u çalıştırmak isterseniz, bir CMD netonly oturumu oluşturabilir ve oradan SharpHound'u çalıştırabilirsiniz:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhound hakkında daha fazla bilgi edinin ired.team'de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r), **Grup Politikası** ile ilişkili Active Directory'deki **açıkları** bulmak için bir araçtır. \
**Herhangi bir alan kullanıcısı** kullanarak alan içindeki bir hosttan **group3r'ı çalıştırmanız** gerekir.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **AD ortamının güvenlik durumunu değerlendirir** ve grafiklerle güzel bir **rapor** sunar.

Bunu çalıştırmak için, `PingCastle.exe` ikili dosyasını çalıştırabilir ve seçeneklerin bir menüsünü sunan bir **etkileşimli oturum** başlatır. Kullanılacak varsayılan seçenek **`healthcheck`** olup, **alan** hakkında bir temel **genel bakış** oluşturacak ve **yanlış yapılandırmaları** ve **zayıflıkları** bulacaktır.&#x20;

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
