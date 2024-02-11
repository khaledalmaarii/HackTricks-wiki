# DDexec / KilaKituExec

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Mazingira

Katika Linux ili kuendesha programu, lazima iwe kama faili, lazima iwe inapatikana kwa njia fulani kupitia mfumo wa faili (hii ndio jinsi `execve()` inavyofanya kazi). Faili hii inaweza kuwepo kwenye diski au kwenye ram (tmpfs, memfd) lakini unahitaji njia ya faili. Hii imefanya iwe rahisi sana kudhibiti ni nini kinachoendeshwa kwenye mfumo wa Linux, inafanya iwe rahisi kugundua vitisho na zana za mshambuliaji au kuzuia jaribio lolote lao la kutekeleza chochote chao kabisa (_kwa mfano_ kutowaruhusu watumiaji wasio na uwezo kuweka faili za kutekelezwa mahali popote).

Lakini mbinu hii iko hapa kubadilisha yote haya. Ikiwa huwezi kuanza mchakato unayotaka... **basi unateka moja iliyopo tayari**.

Mbinu hii inakuwezesha **kupita njia za kawaida za ulinzi kama vile kusoma tu, noexec, orodha nyeupe ya majina ya faili, orodha nyeupe ya hash...**

## Mahitaji

Script ya mwisho inahitaji zana zifuatazo ili kufanya kazi, zinahitaji kuwa inapatikana kwenye mfumo unaoshambuliwa (kwa chaguo-msingi utazipata kote):
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

Ikiwa unaweza kubadilisha kumbukumbu ya mchakato kwa hiari, basi unaweza kuuchukua udhibiti. Hii inaweza kutumika kuiba mchakato uliopo tayari na kuiweka nafasi yake na programu nyingine. Tunaweza kufanikisha hili kwa kutumia syscall ya `ptrace()` (ambayo inahitaji uwezo wa kutekeleza syscalls au kuwa na gdb inapatikana kwenye mfumo) au, zaidi ya hayo, kwa kuandika kwenye `/proc/$pid/mem`.

Faili ya `/proc/$pid/mem` ni ramani moja kwa moja ya nafasi nzima ya anwani ya mchakato (kwa mfano kutoka `0x0000000000000000` hadi `0x7ffffffffffff000` kwenye x86-64). Hii inamaanisha kuwa kusoma au kuandika kwenye faili hii kwenye nafasi ya mbali `x` ni sawa na kusoma au kubadilisha maudhui kwenye anwani ya kawaida `x`.

Sasa, tuna matatizo manne ya msingi ya kukabiliana nayo:

* Kwa ujumla, tu root na mmiliki wa programu ya faili wanaweza kuihariri.
* ASLR.
* Ikiwa tunajaribu kusoma au kuandika kwenye anwani ambayo haipo kwenye nafasi ya anwani ya programu, tutapata kosa la I/O.

Matatizo haya yana suluhisho ambayo, ingawa sio kamili, ni nzuri:

* Winterpreti wengi wa shell huruhusu uundaji wa maelezo ya faili ambayo kisha yataurithiwa na michakato ya watoto. Tunaweza kuunda fd inayoelekeza kwenye faili ya `mem` ya shell na ruhusa za kuandika... kwa hivyo michakato ya watoto ambayo hutumia fd hiyo itaweza kuhariri kumbukumbu ya shell.
* ASLR hata sio tatizo, tunaweza kuangalia faili ya `maps` ya shell au nyingine yoyote kutoka kwenye procfs ili kupata habari kuhusu nafasi ya anwani ya mchakato.
* Kwa hivyo tunahitaji kufanya `lseek()` juu ya faili. Kutoka kwenye shell hii haiwezekani isipokuwa kwa kutumia `dd` maarufu.

### Kwa undani zaidi

Hatua ni rahisi na hazihitaji aina yoyote ya ujuzi wa kuzielewa:

* Tathmini faili tunayotaka kuendesha na mzigo ili kugundua ramani wanazohitaji. Kisha tengeneza "shell"code ambayo itatekeleza, kwa ujumla, hatua sawa ambazo kernel hufanya kwa kila wito wa `execve()`:
* Unda ramani hizo.
* Soma faili za binary ndani yao.
* Weka ruhusa.
* Hatimaye, anzisha stack na hoja za programu na weka vector ya ziada (inayohitajika na mzigo).
* Ruka kwenye mzigo na ruhusu ifanye yake (kupakia maktaba zinazohitajika na programu).
* Pata kutoka kwenye faili ya `syscall` anwani ambayo mchakato utarudi baada ya syscall inayotekelezwa.
* Badilisha mahali hilo, ambalo litakuwa na uwezo wa kutekelezwa, na shellcode yetu (kupitia `mem` tunaweza kubadilisha kurasa zisizoweza kuandikwa).
* Pita programu tunayotaka kuendesha kwa stdin ya mchakato (itakayosomwa na "shell"code hiyo).
* Kwa wakati huu, ni jukumu la mzigo kupakia maktaba muhimu kwa programu yetu na kuruka ndani yake.

**Angalia zana katika** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## KilaKituExec

Kuna njia kadhaa mbadala za `dd`, moja wapo, `tail`, kwa sasa ni programu inayotumiwa kwa chaguo-msingi kwa `lseek()` kupitia faili ya `mem` (ambayo ilikuwa kusudi pekee la kutumia `dd`). Njia mbadala hizo ni:
```bash
tail
hexdump
cmp
xxd
```
Kwa kuweka variable `SEEKER` unaweza kubadilisha mtumiaji wa kutafuta, kwa mfano:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ikiwa utapata mtafuta mwingine halali ambao haujatekelezwa kwenye hati, bado unaweza kutumia kwa kuweka variable ya `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zuia hii, EDRs.

## Marejeo
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
