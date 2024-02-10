# macOS Office Sandbox Geçişleri

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

### Word Sandbox Geçişi Launch Agentlar aracılığıyla

Uygulama, **`com.apple.security.temporary-exception.sbpl`** yetkisi kullanarak **özel bir Sandbox** kullanır ve bu özel Sandbox, dosya adı `~$` ile başladığı sürece herhangi bir yere dosya yazmaya izin verir: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Bu nedenle, kaçış işlemi, `~/Library/LaunchAgents/~$escape.plist` konumunda bir `plist` LaunchAgent'ı yazmak kadar kolaydı.

[**Orijinal rapora buradan**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) bakın.

### Word Sandbox Geçişi Login Öğeleri ve zip ile

İlk kaçıştan hatırlayın, Word, `~$` ile başlayan keyfi dosyalar yazabilir, ancak önceki zafiyetin düzeltmesinden sonra `/Library/Application Scripts` veya `/Library/LaunchAgents` dizinlerine yazmak mümkün olmamıştır.

Sandbox içinden bir **Giriş Öğesi** (kullanıcı oturum açtığında çalıştırılacak uygulamalar) oluşturmanın mümkün olduğu keşfedildi. Ancak, bu uygulamalar **imzalanmadıkça** çalışmayacak ve argüman eklemek mümkün olmayacak (yani **`bash`** kullanarak ters kabuk çalıştıramazsınız).

Önceki Sandbox geçişinden sonra, Microsoft `~/Library/LaunchAgents` dizinine dosya yazma seçeneğini devre dışı bıraktı. Ancak, bir **zip dosyasını Giriş Öğesi** olarak eklerseniz, `Archive Utility` bunu mevcut konumunda sadece **açacaktır**. Bu nedenle, varsayılan olarak `~/Library` dizininde `LaunchAgents` klasörü oluşturulmadığından, `LaunchAgents/~$escape.plist` konumunda bir plist'i sıkıştırıp **zip dosyasını `~/Library`** dizinine yerleştirmek mümkün olmuştur, böylece açıldığında kalıcılık hedefine ulaşacaktır.

[**Orijinal rapora buradan**](https://objective-see.org/blog/blog\_0x4B.html) bakın.

### Word Sandbox Geçişi Login Öğeleri ve .zshenv ile

(İlk kaçıştan hatırlayın, Word, `~$` ile başlayan keyfi dosyalar yazabilir).

Ancak, önceki teknik bir kısıtlamaya sahipti, eğer **`~/Library/LaunchAgents`** dizini başka bir yazılım tarafından oluşturulduysa başarısız olacaktı. Bu nedenle, bunun için farklı bir Login Öğeleri zinciri keşfedildi.

Saldırgan, yürütülecek yükü içeren **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturabilir ve ardından bunları zipleyebilir ve zip dosyasını kurbanın kullanıcı klasörüne **`~/~$escape.zip`** yazabilir.

Daha sonra, zip dosyasını **Login Öğeleri'ne** ve ardından **`Terminal`** uygulamasına ekleyin. Kullanıcı yeniden oturum açtığında, zip dosyası kullanıcının dosyasına sıkıştırılmadan açılacak ve **`.bash_profile`** ve **`.zshenv`** üzerine yazacak ve bu nedenle terminal bu dosyalardan birini yürütecektir (bash veya zsh kullanılıp kullanılmadığına bağlı olarak).

[**Orijinal rapora buradan**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) bakın.

### Word Sandbox Geçişi Open ve env değişkenleri ile

Sandbox süreçlerinden, diğer süreçleri **`open`** yardımıyla çağırmak hala mümkündür. Dahası, bu süreçler kendi Sandbox'larında çalışacaktır.

`open` yardımcı programının, **belirli env** değişkenleriyle bir uygulamayı çalıştırmak için **`--env`** seçeneğine sahip olduğu keşfedildi. Bu nedenle, Sandbox'ın **içinde** bir klasörün içine **`.zshenv` dosyası** oluşturmak ve `open`'ı kullanarak `--env` ile **`HOME` değişkenini** o klasöre ayarlamak ve bu `Terminal` uygulamasını açmak mümkün oldu, bu da `.zshenv` dosyasını yürütecektir (bir nedenle değişken `__OSINSTALL_ENVIROMENT`'in ayarlanması gerekiyordu).

[**Orijinal rapora buradan**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/) bakın.

### Word Sandbox Geçişi Open ve stdin ile

**`open`** yardımcı programı ayrıca **`--stdin`** parametresini de desteklemektedir (ve önceki geçişten sonra `--env` kullanmak artık mümkün değildi).

Mesele şu ki, **`python`** Apple tarafından imzalanmış olsa bile, **`karantina`** özniteliğine sahip bir betiği **çalıştırmaz**. Bununla birlikte, stdin'den bir betik geçirilebildiğinden, karantinaya alınıp alınmadığı kontrol edilmez:&#x20;

1. Keyfi Python komutları içeren bir **`~$exploit.py`** dosyası bırakın.
2. _open_ **`–stdin='~$exploit.py' -a Python`** komutunu çalıştırın, bu da Python uygulamasını bıraktığımız dosya ile standart girişi olarak çalıştırır. Python kodumuzu mutlu bir şekilde çalıştırır ve _launchd_'nin bir alt süreci olduğu için Word'ün sandbox kurallarına bağlı değildir.

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS
