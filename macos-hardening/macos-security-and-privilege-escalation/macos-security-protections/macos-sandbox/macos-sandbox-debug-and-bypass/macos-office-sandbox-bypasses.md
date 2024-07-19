# macOS Office Sandbox Bypasses

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

### Word Sandbox bypass via Launch Agents

Uygulama, **`com.apple.security.temporary-exception.sbpl`** yetkisini kullanarak **özel bir Sandbox** kullanıyor ve bu özel sandbox, dosya adının `~$` ile başlaması koşuluyla her yere dosya yazılmasına izin veriyor: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Bu nedenle, kaçış yapmak **`~/Library/LaunchAgents/~$escape.plist`** içinde bir **`plist`** LaunchAgent yazmak kadar kolaydı.

[**orijinal raporu buradan kontrol edin**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

İlk kaçıştan hatırlayın, Word `~$` ile başlayan rastgele dosyalar yazabilir, ancak önceki güvenlik açığının yamanmasından sonra `/Library/Application Scripts` veya `/Library/LaunchAgents` içine yazmak mümkün değildi.

Sandbox içinde bir **Login Item** (kullanıcı giriş yaptığında çalıştırılacak uygulamalar) oluşturmanın mümkün olduğu keşfedildi. Ancak, bu uygulamalar **notarize edilmedikçe** **çalışmayacak** ve **argüman eklemek mümkün değil** (yani sadece **`bash`** kullanarak bir ters shell çalıştıramazsınız).

Önceki Sandbox kaçışından sonra, Microsoft `~/Library/LaunchAgents` içine dosya yazma seçeneğini devre dışı bıraktı. Ancak, bir **zip dosyasını Login Item olarak koyarsanız**, `Archive Utility` sadece mevcut konumda **açacaktır**. Bu nedenle, varsayılan olarak `~/Library` içindeki `LaunchAgents` klasörü oluşturulmadığı için, **`LaunchAgents/~$escape.plist`** içindeki bir plist'i **zipleyip** **`~/Library`** içine yerleştirmek mümkün oldu, böylece açıldığında kalıcılık hedefine ulaşacaktır.

[**orijinal raporu buradan kontrol edin**](https://objective-see.org/blog/blog\_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(İlk kaçıştan hatırlayın, Word `~$` ile başlayan rastgele dosyalar yazabilir).

Ancak, önceki teknik bir sınırlamaya sahipti; eğer **`~/Library/LaunchAgents`** klasörü başka bir yazılım tarafından oluşturulmuşsa, başarısız oluyordu. Bu nedenle, bunun için farklı bir Login Items zinciri keşfedildi.

Bir saldırgan, çalıştırılacak yüklemi içeren **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturabilir ve ardından bunları zipleyip **kurbanın** kullanıcı klasörüne yazabilirdi: **`~/~$escape.zip`**.

Sonra, zip dosyasını **Login Items**'a ekleyip ardından **`Terminal`** uygulamasını ekleyin. Kullanıcı tekrar giriş yaptığında, zip dosyası kullanıcı dosyasında açılacak, **`.bash_profile`** ve **`.zshenv`** dosyalarını üzerine yazacak ve dolayısıyla terminal bu dosyalardan birini çalıştıracaktır (bash veya zsh kullanılıp kullanılmadığına bağlı olarak).

[**orijinal raporu buradan kontrol edin**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

Sandboxlı süreçlerden, diğer süreçleri **`open`** aracıyla çağırmak hala mümkündür. Dahası, bu süreçler **kendi sandbox'larında** çalışacaktır.

Open aracının **belirli env** değişkenleri ile bir uygulama çalıştırmak için **`--env`** seçeneğine sahip olduğu keşfedildi. Bu nedenle, **sandbox** içinde bir klasör içinde **`.zshenv` dosyası** oluşturmak ve `--env` ile `HOME` değişkenini o klasöre ayarlayarak `Terminal` uygulamasını açmak mümkün oldu; bu, `.zshenv` dosyasını çalıştıracaktır (bir nedenle `__OSINSTALL_ENVIROMENT` değişkenini de ayarlamak gerekiyordu).

[**orijinal raporu buradan kontrol edin**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

**`open`** aracı ayrıca **`--stdin`** parametresini destekliyordu (ve önceki kaçıştan sonra `--env` kullanmak artık mümkün değildi).

Şu durum var ki, **`python`** Apple tarafından imzalanmış olsa da, **`quarantine`** niteliğine sahip bir betiği **çalıştırmaz**. Ancak, stdin'den bir betik geçirebilmek mümkündü, böylece karantinada olup olmadığını kontrol etmeyecekti: 

1. Rastgele Python komutları içeren bir **`~$exploit.py`** dosyası bırakın.
2. _open_ **`–stdin='~$exploit.py' -a Python`** komutunu çalıştırın; bu, Python uygulamasını standart girdi olarak bıraktığımız dosya ile çalıştırır. Python, kodumuzu memnuniyetle çalıştırır ve çünkü bu, _launchd_'nin bir çocuk süreci olduğundan, Word'ün sandbox kurallarına bağlı değildir.

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
