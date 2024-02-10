# DDexec / EverythingExec

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## Bağlam

Linux'ta bir programı çalıştırmak için, dosya olarak var olmalı ve dosya sistemi hiyerarşisi üzerinden bir şekilde erişilebilir olmalıdır (bu sadece `execve()` işlevinin çalışma şeklidir). Bu dosya diskte veya ram'de (tmpfs, memfd) bulunabilir, ancak bir dosya yolu gereklidir. Bu, Linux sistemde çalıştırılan şeyi kontrol etmeyi çok kolay hale getirir, tehditleri ve saldırgan araçlarını tespit etmeyi veya onların hiçbir şeyini çalıştırmalarına izin vermemeyi kolaylaştırır (_örneğin_, ayrıcalığı olmayan kullanıcıların yürütülebilir dosyaları herhangi bir yere yerleştirmelerine izin vermemek).

Ancak bu teknik, tüm bunları değiştirmek için burada. İstediğiniz süreci başlatamazsanız... **zaten var olan bir süreci ele geçirirsiniz**.

Bu teknik, **salt okunur, noexec, dosya adı beyaz listeleme, hash beyaz listeleme gibi yaygın koruma tekniklerini atlamak** için kullanılabilir.

## Bağımlılıklar

Son komut dosyasının çalışması için aşağıdaki araçlara bağımlılığı vardır, saldırdığınız sistemde erişilebilir olmaları gerekmektedir (varsayılan olarak hepsini her yerde bulabilirsiniz):
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

Bir sürecin belleğini keyfi olarak değiştirebiliyorsanız, onu ele geçirebilirsiniz. Bu, zaten var olan bir süreci ele geçirmek ve başka bir programla değiştirmek için kullanılabilir. Bunun için ya `ptrace()` sistem çağrısını kullanarak (sistemde syscalls çalıştırma yeteneğine veya gdb'nin sistemde bulunmasına ihtiyaç duyar) veya daha ilginç olanı, `/proc/$pid/mem` dosyasına yazarak başarabiliriz.

`/proc/$pid/mem` dosyası, bir sürecin tüm adres alanının (_örn. x86-64'te `0x0000000000000000` ile `0x7ffffffffffff000` arasında_) birbirine eşleştirilmesidir. Bu, bir ofset `x` ile bu dosyadan okuma veya yazma, sanal adres `x`'teki içeriği okuma veya değiştirmeyle aynıdır.

Şimdi, üstesinden gelmemiz gereken dört temel sorunumuz var:

* Genel olarak, yalnızca kök ve dosyanın program sahibi tarafından değiştirilebilir.
* ASLR.
* Programın adres alanında eşlenmemiş bir adrese okuma veya yazma denememiz durumunda bir G/Ç hatası alırız.

Bu sorunların, mükemmel olmasa da iyi çözümleri vardır:

* Çoğu kabuk yorumlayıcısı, ardından çocuk süreçler tarafından devralınacak dosya tanımlayıcılarının oluşturulmasına izin verir. Yazma izinleriyle kabuğun `mem` dosyasına işaret eden bir fd oluşturabiliriz... böylece bu fd'yi kullanan çocuk süreçler, kabuğun belleğini değiştirebilecektir.
* ASLR bile bir sorun değil, programın adres alanı hakkında bilgi edinmek için kabuğun `maps` dosyasını veya procfs'ten başka bir dosyayı kontrol edebiliriz.
* Bu yüzden dosya üzerinde `lseek()` yapmamız gerekiyor. Kabuktan bu yapılamaz, ancak kötü şöhretli `dd` kullanılarak yapılabilir.

### Daha detaylı olarak

Adımlar oldukça kolaydır ve bunları anlamak için herhangi bir uzmanlık gerektirmez:

* Çalıştırmak istediğimiz ikili ve yükleyiciyi analiz edin ve hangi eşlemelere ihtiyaç duyduklarını bulun. Ardından, her bir `execve()` çağrısında çekirdeğin yaptığı adımların genel olarak aynısını gerçekleştirecek bir "shell" kodu oluşturun:
* Söz konusu eşlemeleri oluşturun.
* İkili dosyaları bunlara okuyun.
* İzinleri ayarlayın.
* Son olarak, programın argümanları için yığını başlatın ve yükleyici tarafından gereken yardımcı vektörü yerleştirin.
* Yükleyiciye atlayın ve gerisini ona bırakın (program tarafından gereken kütüphaneleri yükleyin).
* İşlem tarafından gerçekleştirilen sistem çağrısından sonra döneceği adresi `syscall` dosyasından alın.
* Bu, yazılabilir olmayan sayfaları `mem` aracılığıyla değiştirebileceğimiz bir yer olan, yürütülebilir olan yere kendi shell kodumuzu üzerine yazın.
* Çalıştırmak istediğimiz programı sürecin stdin'ine geçirin (söz konusu "shell" kodu tarafından `read()` edilecektir).
* Bu noktada, programımız için gerekli kütüphaneleri yüklemek ve ona atlamak yükleyiciye bağlıdır.

**Araç için** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec) **adresine bakın**

## EverythingExec

`dd`'ye alternatif olarak birkaç seçenek vardır, bunlardan biri olan `tail`, `mem` dosyası üzerinde `lseek()` yapmak için şu anda varsayılan olarak kullanılan programdır (`dd` kullanmanın tek amacı buydu). Söz konusu alternatifler şunlardır:
```bash
tail
hexdump
cmp
xxd
```
Değişken `SEEKER`'ı ayarlayarak kullanılan arayıcıyı değiştirebilirsiniz, örneğin:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Eğer betikte uygulanmamış başka geçerli bir arayıcı bulursanız, `SEEKER_ARGS` değişkenini ayarlayarak hala kullanabilirsiniz:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Engelleyin bunu, EDR'lar.

## Referanslar
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın**.

</details>
