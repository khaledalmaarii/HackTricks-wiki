# PID Namespace

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
{% endhint %}

## Temel Bilgiler

PID (Process IDentifier) namespace, Linux çekirdeğinde, bir grup sürecin kendi benzersiz PID'lerine sahip olmasını sağlayarak süreç izolasyonu sağlayan bir özelliktir. Bu, süreç izolasyonunun güvenlik ve kaynak yönetimi için hayati olduğu konteynerleştirmede özellikle yararlıdır.

Yeni bir PID namespace oluşturulduğunda, o namespace içindeki ilk süreç PID 1 ile atanır. Bu süreç, yeni namespace'in "init" süreci haline gelir ve namespace içindeki diğer süreçleri yönetmekten sorumludur. Namespace içinde oluşturulan her bir sonraki süreç, o namespace içinde benzersiz bir PID alır ve bu PID'ler diğer namespace'lerdeki PID'lerden bağımsızdır.

Bir PID namespace içindeki bir süreç açısından, yalnızca aynı namespace içindeki diğer süreçleri görebilir. Diğer namespace'lerdeki süreçlerden haberdar değildir ve geleneksel süreç yönetim araçları (örneğin, `kill`, `wait`, vb.) kullanarak onlarla etkileşimde bulunamaz. Bu, süreçlerin birbirine müdahale etmesini önlemeye yardımcı olan bir izolasyon seviyesi sağlar.

### Nasıl çalışır:

1. Yeni bir süreç oluşturulduğunda (örneğin, `clone()` sistem çağrısı kullanılarak), süreç yeni veya mevcut bir PID namespace'ine atanabilir. **Yeni bir namespace oluşturulursa, süreç o namespace'in "init" süreci olur**.
2. **Çekirdek**, yeni namespace'deki PID'ler ile ana namespace'deki (yani yeni namespace'in oluşturulduğu namespace) karşılık gelen PID'ler arasında bir **eşleme** tutar. Bu eşleme, **çekirdeğin gerekli olduğunda PID'leri çevirmesine olanak tanır**, örneğin farklı namespace'lerdeki süreçler arasında sinyaller gönderirken.
3. **Bir PID namespace içindeki süreçler yalnızca aynı namespace içindeki diğer süreçleri görebilir ve onlarla etkileşimde bulunabilir**. Diğer namespace'lerdeki süreçlerden haberdar değillerdir ve PID'leri kendi namespace'lerinde benzersizdir.
4. **Bir PID namespace yok edildiğinde** (örneğin, namespace'in "init" süreci çıktığında), **o namespace içindeki tüm süreçler sonlandırılır**. Bu, namespace ile ilişkili tüm kaynakların düzgün bir şekilde temizlenmesini sağlar.

## Laboratuvar:

### Farklı Namespace'ler Oluşturma

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Ana detaylar ve çözüm aşağıda özetlenmiştir:

1. **Sorun Açıklaması**:
- Linux çekirdeği, bir sürecin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanı oluşturma işlemini başlatan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmez; yalnızca onun çocuk süreçleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanındadır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, o ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:
- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluştururken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine neden olur ve "Bellek tahsis edilemiyor" hatasını üretir.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanını oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını garanti eder. `/bin/bash` ve onun çocuk süreçleri, bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare`'in `-f` bayrağı ile çalıştırılmasını sağlayarak, yeni PID ad alanının doğru bir şekilde korunmasını sağlarsınız, böylece `/bin/bash` ve alt süreçleri bellek tahsis hatası ile karşılaşmadan çalışabilir.

</details>

Yeni bir `/proc` dosya sisteminin örneğini `--mount-proc` parametresini kullanarak monte ederek, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerini doğru ve izole bir şekilde görmesini** sağlarsınız.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Tüm PID ad alanlarını bul

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Başlangıç (varsayılan) PID ad alanındaki root kullanıcısının, yeni PID ad alanlarındaki süreçler de dahil olmak üzere tüm süreçleri görebileceğini unutmayın, bu yüzden tüm PID ad alanlarını görebiliyoruz.

### Bir PID ad alanına girin
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
PID ad alanına varsayılan ad alanından girdiğinizde, tüm süreçleri görebilirsiniz. Ve o PID ns'deki süreç, PID ns'deki yeni bash'i görebilecektir.

Ayrıca, **başka bir süreç PID ad alanına yalnızca root iseniz girebilirsiniz**. Ve **bir tanımlayıcı olmadan** **başka bir ad alanına giremezsiniz** (örneğin `/proc/self/ns/pid` gibi).

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
</details>
{% endhint %}
