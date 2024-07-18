# DDexec / KilaKituExec

{% hint style="success" %}
Jifunze & zoezi Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Muktadha

Katika Linux ili kuendesha programu lazima iwe kama faili, lazima iwe inapatikana kwa njia fulani kupitia muundo wa mfumo wa faili (hii ni tu jinsi `execve()` inavyofanya kazi). Faili hii inaweza kuwepo kwenye diski au kwenye ram (tmpfs, memfd) lakini unahitaji njia ya faili. Hii imefanya iwe rahisi sana kudhibiti nini kinachotumika kwenye mfumo wa Linux, inafanya iwe rahisi kugundua vitisho na zana za mshambuliaji au kuzuia jaribio lao la kutekeleza chochote chao kabisa (_k.m._ kuzuia watumiaji wasio na ruhusa kuweka faili za kutekelezeka mahali popote).

Lakini mbinu hii iko hapa kubadilisha haya yote. Ikiwa huwezi kuanzisha mchakato unayotaka... **basi unateka moja iliyopo tayari**.

Mbinu hii inakuruhusu **kupita mbinu za kawaida za ulinzi kama vile kusoma tu, noexec, orodha nyeupe ya majina ya faili, orodha nyeupe ya hash...**

## Mahitaji

Skripti ya mwisho inategemea zana zifuatazo kufanya kazi, zinahitaji kupatikana kwenye mfumo unao shambuliwa (kwa chaguo-msingi utazipata zote kila mahali):
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
## Mbinu

Ikiwa unaweza kubadilisha kumbukumbu ya mchakato kwa hiari basi unaweza kuuteka. Hii inaweza kutumika kuiba mchakato uliopo tayari na kuiweka nafasi yake na programu nyingine. Tunaweza kufanikisha hili kwa kutumia syscall ya `ptrace()` (ambayo inahitaji uwezo wa kutekeleza syscalls au kuwa na gdb inapatikana kwenye mfumo) au, kwa njia ya kuvutia zaidi, kwa kuandika kwenye `/proc/$pid/mem`.

Faili `/proc/$pid/mem` ni ramani moja kwa moja ya nafasi nzima ya anwani ya mchakato (_k.m._ kutoka `0x0000000000000000` hadi `0x7ffffffffffff000` kwenye x86-64). Hii inamaanisha kwamba kusoma au kuandika kwenye faili hii kwenye mbadala `x` ni sawa na kusoma au kubadilisha maudhui kwenye anwani ya kivinjari `x`.

Sasa, tuna matatizo manne ya msingi ya kukabiliana nayo:

* Kwa ujumla, tu root na mmiliki wa programu ya faili wanaweza kuibadilisha.
* ASLR.
* Ikiwa jaribu kusoma au kuandika kwenye anwani ambayo haipo ramani kwenye nafasi ya anwani ya programu tutapata kosa la I/O.

Matatizo haya yana suluhisho ambayo, ingawa si kamili, ni mazuri:

* Winterpreti wengi wa shell kuruhusu uundaji wa maelezo ya faili ambayo kisha yataurithiwa na michakato ya watoto. Tunaweza kuunda fd inayoashiria faili ya `mem` ya kuuza na ruhusa za kuandika... hivyo michakato ya watoto wanaotumia fd hiyo wataweza kubadilisha kumbukumbu ya kuuza.
* ASLR hata si tatizo, tunaweza kuangalia faili za `maps` za kuuza au nyingine yoyote kutoka kwa procfs ili kupata habari kuhusu nafasi ya anwani ya mchakato.
* Kwa hivyo tunahitaji kufanya `lseek()` kwenye faili. Kutoka kwa kuuza hii haiwezi kufanywa isipokuwa kwa kutumia `dd` inayojulikana.

### Kwa undani zaidi

Hatua ni rahisi kiasi na hazihitaji aina yoyote ya ujuzi wa kuzielewa:

* Tafsiri binary tunayotaka kukimbia na loader ili kugundua ramani wanazohitaji. Kisha tengeneza "shell"code ambayo itatekeleza, kwa ujumla, hatua sawa ambazo kernel hufanya kwa kila wito wa `execve()`:
* Unda ramani hizo.
* Soma binaries ndani yao.
* Weka ruhusa.
* Hatimaye anzisha steki na hoja za programu na weka vector ya ziada (inayohitajika na loader).
* Ruka ndani ya loader na ruhusu ifanye mengine (paki za maktaba zinazohitajika na programu).
* Pata kutoka kwa faili ya `syscall` anwani ambayo mchakato utarejea baada ya syscall inayotekelezwa.
* Badilisha mahali hilo, ambalo litakuwa la kutekelezeka, na shellcode yetu (kupitia `mem` tunaweza kubadilisha kurasa zisizoweza kuandikwa).
* Pita programu tunayotaka kukimbia kwa stdin ya mchakato (itakayosomwa na "shell"code hiyo).
* Kufikia hatua hii ni jukumu la loader kupakia maktaba muhimu kwa programu yetu na kuruka ndani yake.

**Angalia zana katika** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## KilaKituKitekelezwe

Kuna mbadala kadhaa kwa `dd`, moja wapo, `tail`, kwa sasa ni programu ya chaguo inayotumiwa kufanya `lseek()` kupitia faili ya `mem` (ambayo ilikuwa kusudi pekee la kutumia `dd`). Mbadala hao ni:
```bash
tail
hexdump
cmp
xxd
```
Kwa kuweka kipengele `SEEKER` unaweza kubadilisha mtu anayetumika, _k.m._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ikiwa utapata mtu mwingine anayetafuta halali ambaye hajatekelezwa kwenye script unaweza bado kutumia kwa kuweka `SEEKER_ARGS` variable:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
## Marejeo
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
