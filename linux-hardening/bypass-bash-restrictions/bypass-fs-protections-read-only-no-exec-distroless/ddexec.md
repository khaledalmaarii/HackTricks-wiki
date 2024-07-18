# DDexec / EverythingExec

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Bağlam

Linux'ta bir programı çalıştırmak için bir dosya olarak var olmalı, dosya sistemi hiyerarşisi üzerinden bir şekilde erişilebilir olmalıdır (bu sadece `execve()`'nin nasıl çalıştığını gösterir). Bu dosya diskte veya bellekte (tmpfs, memfd) bulunabilir ancak bir dosya yolu gereklidir. Bu, Linux sistemlerinde çalıştırılan şeyi kontrol etmeyi çok kolay hale getirmiştir, tehditleri ve saldırganın araçlarını tespit etmeyi veya onların hiçbir şeyini çalıştırmalarını engellemeyi kolaylaştırır (_ör._ ayrıcalıklı olmayan kullanıcıların herhangi bir yürütülebilir dosyayı herhangi bir yere yerleştirmelerine izin vermemek).

Ancak bu teknik, tüm bunları değiştirmek için burada. Eğer istediğiniz işlemi başlatamıyorsanız... **o zaman zaten var olan bir işlemi ele geçirin**.

Bu teknik, **salt okunur, noexec, dosya adı beyaz listeleme, hash beyaz listeleme gibi yaygın koruma tekniklerini atlamayı** sağlar.

## Bağımlılıklar

Son betik, çalışması için aşağıdaki araçlara bağlıdır, saldırdığınız sistemde erişilebilir olmaları gerekir (varsayılan olarak hepsini her yerde bulabilirsiniz):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Teknik

Eğer bir işlemin belleğini keyfi olarak değiştirebiliyorsanız, onu ele geçirebilirsiniz. Bu, zaten var olan bir işlemi ele geçirip başka bir programla değiştirmek için kullanılabilir. Bunu ya `ptrace()` sistem çağrısını kullanarak (ki bunun için sistem çağrılarını yürütme yeteneğine veya sistemde gdb'nin bulunmasına ihtiyacınız vardır) ya da daha ilginç bir şekilde `/proc/$pid/mem` dosyasına yazarak başarabiliriz.

`/proc/$pid/mem` dosyası, bir işlemin tüm adres alanının (_ör._ x86-64'te `0x0000000000000000` ile `0x7ffffffffffff000` arasından) birbirine eşlenmiş bir görüntüsüdür. Bu, bu dosyadan bir ofset `x`'ten okuma veya yazma işlemi yapmanın, sanal adres `x`'teki içeriği okuma veya değiştirme işlemi yapmakla aynı olduğu anlamına gelir.

Şimdi, üstesinden gelmemiz gereken dört temel sorunumuz var:

* Genel olarak, yalnızca kök ve dosyanın program sahibi tarafından değiştirilebilir.
* ASLR.
* Programın adres alanında eşlenmemiş bir adrese okuma veya yazma denememiz durumunda bir G/Ç hatası alırız.

Bu sorunların, mükemmel olmasa da iyi olan çözümleri vardır:

* Çoğu kabuk yorumlayıcısı, çocuk işlemler tarafından devralınacak dosya tanımlayıcılarının oluşturulmasına izin verir. Yazma izinlerine sahip olan kabuk dosyasına işaret eden bir fd oluşturabiliriz... böylece bu fd'yi kullanan çocuk işlemleri kabuğun belleğini değiştirebilecektir.
* ASLR bile bir sorun değil, programın adres alanı hakkında bilgi edinmek için kabuğun `maps` dosyasını veya procfs'ten başka herhangi bir dosyayı kontrol edebiliriz.
* Bu nedenle dosya üzerinde `lseek()` yapmamız gerekiyor. Kabuktan bu yapılamaz, ancak ünlü `dd` kullanılarak yapılabilir.

### Daha Detaylı

Adımlar oldukça kolaydır ve bunları anlamak için herhangi bir uzmanlık türüne ihtiyaç duymazlar:

* Çalıştırmak istediğimiz ikili dosyayı ve yükleyiciyi ayrıştırarak ihtiyaç duydukları eşlemeleri bulun. Daha sonra, her `execve()` çağrısında çekirdeğin yaptığı genel olarak aynı adımları gerçekleştirecek bir "kabuk" kodu oluşturun:
* Söz konusu eşlemeleri oluşturun.
* İkili dosyaları içlerine okuyun.
* İzinleri ayarlayın.
* Son olarak, program için argümanlarla yığını başlatın ve yükleyici tarafından gereken yardımcı vektörü yerleştirin.
* Yükleyiciye atlayın ve gerisini ona bırakın (program tarafından gereken kütüphaneleri yükleyin).
* İşlemi yürüten sistem çağrısı dosyasından, işlemi yürüttükten sonra geri döneceği adresi alın.
* Bu yere, yürütülebilir olacak şekilde, kendi kabuk kodumuzu (`mem` aracılığıyla yazılamayan sayfaları değiştirebiliriz) üzerine yazın.
* Çalıştırmak istediğimiz programı işlemin stdin'ine geçirin (bu, söz konusu "kabuk" kodu tarafından `read()` edilecektir).
* Bu noktada, programımız için gerekli kütüphaneleri yüklemek ve ona atlamak yükleyiciye kalmıştır.

**Araç için** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd`'ye alternatif olarak birkaç seçenek bulunmaktadır, bunlardan biri olan `tail`, şu anda `mem` dosyası üzerinde `lseek()` yapmak için varsayılan olarak kullanılan programdır (`dd` kullanmanın tek amacı buydu). Söz konusu alternatifler şunlardır:
```bash
tail
hexdump
cmp
xxd
```
Değişken `SEEKER` ayarlanarak kullanılan seeker değiştirilebilir, _ör._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Eğer betikte uygulanmamış başka geçerli bir arayıcı bulursanız, yine de `SEEKER_ARGS` değişkenini ayarlayarak kullanabilirsiniz:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
## Referanslar
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
