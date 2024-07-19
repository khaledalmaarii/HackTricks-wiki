# Ağ Adnamesi

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Temel Bilgiler

Ağ adnamesi, **her ağ adnamesinin kendi bağımsız ağ yapılandırmasına sahip olmasını** sağlayan, ağ yığınını izole eden bir Linux çekirdek özelliğidir; arayüzler, IP adresleri, yönlendirme tabloları ve güvenlik duvarı kuralları. Bu izolasyon, her konteynerin diğer konteynerlerden ve ana sistemden bağımsız kendi ağ yapılandırmasına sahip olması gereken konteynerleştirme gibi çeşitli senaryolar için faydalıdır.

### Nasıl çalışır:

1. Yeni bir ağ adnamesi oluşturulduğunda, **tamamen izole bir ağ yığını** ile başlar; sadece döngü arayüzü (lo) dışında **hiçbir ağ arayüzü** yoktur. Bu, yeni ağ adnamesinde çalışan süreçlerin varsayılan olarak diğer adnamelerdeki veya ana sistemdeki süreçlerle iletişim kuramayacağı anlamına gelir.
2. veth çiftleri gibi **sanal ağ arayüzleri** oluşturulabilir ve ağ adnameleri arasında taşınabilir. Bu, adnameler arasında veya bir adnamesi ile ana sistem arasında ağ bağlantısı kurmayı sağlar. Örneğin, bir veth çiftinin bir ucu bir konteynerin ağ adnamesine yerleştirilebilir ve diğer ucu ana adnamede bir **köprüye** veya başka bir ağ arayüzüne bağlanarak konteynere ağ bağlantısı sağlar.
3. Bir adnamesi içindeki ağ arayüzleri, diğer adnamelerden bağımsız olarak **kendi IP adreslerine, yönlendirme tablolarına ve güvenlik duvarı kurallarına** sahip olabilir. Bu, farklı ağ adnamelerindeki süreçlerin farklı ağ yapılandırmalarına sahip olmasını ve ayrı ağ sistemlerinde çalışıyormuş gibi işlem yapmasını sağlar.
4. Süreçler, `setns()` sistem çağrısını kullanarak adnameler arasında hareket edebilir veya `CLONE_NEWNET` bayrağı ile `unshare()` veya `clone()` sistem çağrılarını kullanarak yeni adnameler oluşturabilir. Bir süreç yeni bir adnamesine geçtiğinde veya bir tane oluşturduğunda, o adnamesi ile ilişkili ağ yapılandırmasını ve arayüzlerini kullanmaya başlayacaktır.

## Laboratuvar:

### Farklı Adnameler Oluşturma

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Yeni bir `/proc` dosya sisteminin örneğini `--mount-proc` parametresi ile monte ederek, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerine doğru ve izole bir görünüm** sağladığınızı garanti edersiniz.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Anahtar detaylar ve çözüm aşağıda özetlenmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir sürecin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanı oluşturma işlemini başlatan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmemektedir; yalnızca onun çocuk süreçleri girmektedir.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanında kalır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, bu ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:
- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluşturulurken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine neden olur ve "Bellek tahsis edilemiyor" hatasını üretir.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanını oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını garanti eder. `/bin/bash` ve onun çocuk süreçleri bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare`'in `-f` bayrağı ile çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ile alt süreçlerinin bellek tahsis hatası ile karşılaşmadan çalışmasına olanak tanır.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Tüm Ağ ad alanlarını Bul

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Bir Ağ ad alanına girin
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Ayrıca, **başka bir işlem ad alanına yalnızca root iseniz girebilirsiniz**. Ve **başka bir ad alanına** **giremezsiniz** **onu işaret eden bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/net`).

## References
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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
