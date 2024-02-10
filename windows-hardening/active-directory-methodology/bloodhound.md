# BloodHound ve Diğer AD Enum Araçları

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) alın
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer), Sysinternal Suite'den bir araçtır:

> Gelişmiş bir Active Directory (AD) görüntüleyici ve düzenleyicidir. AD Explorer'ı kullanarak AD veritabanında kolayca gezinebilir, favori konumları tanımlayabilir, nesne özelliklerini ve özniteliklerini açmadan görüntüleyebilir, izinleri düzenleyebilir, bir nesnenin şemasını görüntüleyebilir ve kaydedip yeniden çalıştırabileceğiniz karmaşık aramaları gerçekleştirebilirsiniz.

### Anlık Görüntüler

AD Explorer, AD'nin bir anlık görüntülerini oluşturabilir, böylece çevrimdışı olarak kontrol edebilirsiniz.\
Bu, çevrimdışı olarak zafiyetleri keşfetmek veya AD DB'nin farklı durumlarını karşılaştırmak için kullanılabilir.

AD'nin bir anlık görüntüsünü almak için, `File` --> `Create Snapshot`'a gidin ve bir görüntü için bir ad girin.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon), bir AD ortamından çeşitli verileri çıkaran ve birleştiren bir araçtır. Bilgiler, analizi kolaylaştırmak ve hedef AD ortamının mevcut durumunun bütünsel bir resmini sağlamak için özet görünümler içeren **özel olarak biçimlendirilmiş** bir Microsoft Excel **raporu** şeklinde sunulabilir.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

[https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound) adresinden alınmıştır.

> BloodHound, [Linkurious](http://linkurio.us/) üzerine inşa edilmiş, [Electron](http://electron.atom.io/) ile derlenmiş, C# veri toplayıcı tarafından beslenen bir Neo4j veritabanıyla çalışan tek sayfalık bir JavaScript web uygulamasıdır.

BloodHound, graf teorisi kullanarak Active Directory veya Azure ortamında gizli ve genellikle istenmeyen ilişkileri ortaya çıkarır. Saldırganlar, BloodHound'u kullanarak aksi takdirde hızlı bir şekilde tespit edilemeyecek karmaşık saldırı yollarını kolayca belirleyebilir. Savunma ekipleri, BloodHound'u aynı saldırı yollarını belirlemek ve ortadan kaldırmak için kullanabilir. Hem mavi hem de kırmızı takımlar, BloodHound'u Active Directory veya Azure ortamında ayrıcalık ilişkilerini daha iyi anlamak için kolayca kullanabilir.

Bu nedenle, [Bloodhound](https://github.com/BloodHoundAD/BloodHound), bir etki alanını otomatik olarak numaralandırabilen, tüm bilgileri kaydedebilen, olası ayrıcalık yükseltme yollarını bulabilen ve grafikler kullanarak tüm bilgileri gösterebilen harika bir araçtır.

Bloodhound, **ingestörler** ve **görselleştirme uygulaması** olmak üzere iki ana bölümden oluşur.

**Ingestörler**, etki alanını **numaralandırmak ve tüm bilgileri çıkarmak** için kullanılır ve görselleştirme uygulamasının anlayabileceği bir formatta veri toplar.

**Görselleştirme uygulaması neo4j** kullanarak tüm bilgilerin nasıl ilişkili olduğunu ve etki alanında ayrıcalıkları yükseltmek için farklı yolları gösterir.

### Kurulum
BloodHound CE'nin oluşturulmasından sonra, tüm proje Docker ile kolay kullanım için güncellendi. Başlamak için en kolay yol, önceden yapılandırılmış Docker Compose yapılandırmasını kullanmaktır.

1. Docker Compose'u yükleyin. Bu, [Docker Desktop](https://www.docker.com/products/docker-desktop/) kurulumuyla birlikte gelmelidir.
2. Çalıştırın:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Docker Compose'in terminal çıktısında rastgele oluşturulan şifreyi bulun.
4. Bir tarayıcıda http://localhost:8080/ui/login adresine gidin. Kullanıcı adı olarak admin ve günlüklerden elde edilen rastgele oluşturulan şifre ile giriş yapın.

Bundan sonra rastgele oluşturulan şifreyi değiştirmeniz gerekecek ve yeni arayüzü hazır olacak, bu arayüzden doğrudan ingestorları indirebilirsiniz.

### SharpHound

Birkaç seçenekleri var, ancak etki alanına katılmış bir PC'den SharpHound'u çalıştırmak, mevcut kullanıcınızı kullanarak tüm bilgileri çıkarmak istiyorsanız, aşağıdaki adımları izleyebilirsiniz:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod** hakkında daha fazla bilgi edinebilir ve döngü oturumunu [buradan](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained) okuyabilirsiniz.

Farklı kimlik bilgileri kullanarak SharpHound'u çalıştırmak isterseniz, CMD netonly oturumu oluşturabilir ve SharpHound'u oradan çalıştırabilirsiniz:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhound hakkında daha fazla bilgi için ired.team'a göz atın.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r), Active Directory ile ilişkili **Grup Politikası**'ndaki **zayıflıkları** bulmak için bir araçtır. \
Herhangi bir etki alanı kullanıcısı kullanarak etki alanı içindeki bir ana bilgisayardan **group3r'ı çalıştırmanız gerekmektedir**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **AD ortamının güvenlik durumunu değerlendirir** ve güzel bir **rapor** sunar.

Çalıştırmak için, `PingCastle.exe` ikili dosyasını çalıştırabilirsiniz ve etkileşimli bir oturum başlatacaktır. Bir seçenek menüsü sunar. Kullanılması gereken varsayılan seçenek **`healthcheck`**'tir. Bu seçenek, **alanın** bir **genel bakışını** oluşturacak ve **yanlış yapılandırmaları** ve **zayıflıkları** bulacaktır.&#x20;

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
