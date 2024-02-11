# Gebruikersnaamruimte

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

'n Gebruikersnaamruimte is 'n Linux-kernelkenmerk wat **afsondering van gebruikers- en groep-ID-toewysings bied**, wat elke gebruikersnaamruimte in staat stel om sy **eie stel gebruikers- en groep-ID's** te hê. Hierdie afsondering maak dit moontlik dat prosesse wat in verskillende gebruikersnaamruimtes loop, **verskillende voorregte en eienaarskap het**, selfs as hulle dieselfde gebruikers- en groep-ID's numeries deel.

Gebruikersnaamruimtes is veral nuttig in konteinering, waar elke kontainer sy eie onafhanklike stel gebruikers- en groep-ID's moet hê, wat beter sekuriteit en afsondering tussen konteinere en die gasheerstelsel moontlik maak.

### Hoe dit werk:

1. Wanneer 'n nuwe gebruikersnaamruimte geskep word, **begin dit met 'n leë stel gebruikers- en groep-ID-toewysings**. Dit beteken dat enige proses wat in die nuwe gebruikersnaamruimte loop, **aanvanklik geen voorregte buite die naamruimte het nie**.
2. ID-toewysings kan tot stand gebring word tussen die gebruikers- en groep-ID's in die nuwe naamruimte en dié in die ouer (of gasheer) naamruimte. Dit **maak dit moontlik dat prosesse in die nuwe naamruimte voorregte en eienaarskap het wat ooreenstem met die gebruikers- en groep-ID's in die ouer naamruimte**. Die ID-toewysings kan egter beperk word tot spesifieke reekse en subsets van ID's, wat fynbeheerde beheer oor die voorregte wat aan prosesse in die nuwe naamruimte verleen word, moontlik maak.
3. Binne 'n gebruikersnaamruimte kan **prosesse volle root-voorregte (UID 0) hê vir operasies binne die naamruimte**, terwyl hulle steeds beperkte voorregte buite die naamruimte het. Dit maak dit moontlik dat **konteinere met root-agtige vermoëns binne hul eie naamruimte kan loop sonder om volle root-voorregte op die gasheerstelsel te hê**.
4. Prosesse kan tussen naamruimtes beweeg deur die `setns()`-sisteemaanroep te gebruik of nuwe naamruimtes te skep deur die `unshare()`- of `clone()`-sisteemaanroep met die `CLONE_NEWUSER`-vlag te gebruik. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, begin dit die gebruikers- en groep-ID-toewysings wat met daardie naamruimte geassosieer is, gebruik.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc`-lêersisteem te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe berg-namespace 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie namespace** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` uitgevoer word sonder die `-f`-opsie, word 'n fout aangetref as gevolg van die manier waarop Linux nuwe PID (Proses-ID) namespaces hanteer. Die sleuteldetails en die oplossing word hieronder uiteengesit:

1. **Probleemverduideliking**:
- Die Linux-kernel maak dit moontlik vir 'n proses om nuwe namespaces te skep deur die `unshare`-stelseloproep te gebruik. Die proses wat die skepping van 'n nuwe PID-namespace inisieer (bekend as die "unshare"-proses) betree egter nie die nuwe namespace nie; slegs sy kinderprosesse doen dit.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kinderprosesse in die oorspronklike PID-namespace.
- Die eerste kinderproses van `/bin/bash` in die nuwe namespace word PID 1. Wanneer hierdie proses afsluit, veroorsaak dit die skoonmaak van die namespace as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kernel sal dan PID-toekenning in daardie namespace deaktiveer.

2. **Gevolg**:
- Die afsluiting van PID 1 in 'n nuwe namespace lei tot die skoonmaak van die `PIDNS_HASH_ADDING`-vlag. Dit veroorsaak dat die `alloc_pid`-funksie misluk om 'n nuwe PID toe te ken wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" -fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f`-opsie saam met `unshare` te gebruik. Hierdie opsie maak `unshare` 'n nuwe proses na die skepping van die nuwe PID-namespace.
- Deur `%unshare -fp /bin/bash%` uit te voer, verseker jy dat die `unshare`-opdrag self PID 1 in die nuwe namespace word. `/bin/bash` en sy kinderprosesse word dan veilig binne hierdie nuwe namespace gehou, wat die voortydige afsluiting van PID 1 voorkom en normale PID-toekenning moontlik maak.

Deur te verseker dat `unshare` met die `-f`-vlag uitgevoer word, word die nuwe PID-namespace korrek onderhou, sodat `/bin/bash` en sy subprosesse kan werk sonder om die geheue-toewysingsfout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Om gebruikersnaamruimte te gebruik, moet die Docker-daemon begin word met **`--userns-remap=default`** (In Ubuntu 14.04 kan dit gedoen word deur `/etc/default/docker` te wysig en dan `sudo service docker restart` uit te voer)

### &#x20;Kyk in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Dit is moontlik om die gebruikerskaart van die Docker-container te kontroleer met:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Of vanaf die gasheer met:
```bash
cat /proc/<pid>/uid_map
```
### Vind alle Gebruiker namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Betree binne 'n Gebruikersnaamruimte

Om binne 'n gebruikersnaamruimte in te gaan, kan jy die volgende stappe volg:

1. Kyk na die huidige gebruikersnaamruimte-inligting deur die volgende opdrag uit te voer:
   ```
   cat /proc/$$/uid_map
   ```

2. Maak 'n nuwe gebruikersnaamruimte met behulp van die volgende opdrag:
   ```
   unshare --user
   ```

3. Bevestig dat jy binne die nuwe gebruikersnaamruimte is deur die volgende opdrag uit te voer:
   ```
   cat /proc/$$/uid_map
   ```

Deur hierdie stappe te volg, kan jy binne 'n gebruikersnaamruimte binnekom en die relevante funksies en bevoegdhede daarvan verken.
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Verder kan jy slegs **toegang kry tot 'n ander proses-namespace as jy root is**. En jy **kan nie** **toegang kry** tot 'n ander namespace **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/user`).

### Skep 'n nuwe Gebruikers-namespace (met karterings)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Herstel van Vaardighede

In die geval van gebruikersnamespaces, **wanneer 'n nuwe gebruikersnamespace geskep word, word die proses wat die namespace betree, 'n volledige stel vaardighede binne daardie namespace toegeken**. Hierdie vaardighede stel die proses in staat om bevoorregte handelinge uit te voer soos **die koppel van lêersisteme**, die skep van toestelle, of die verandering van eienaarskap van lêers, maar **slegs binne die konteks van sy gebruikersnamespace**.

Byvoorbeeld, as jy die `CAP_SYS_ADMIN` vaardigheid binne 'n gebruikersnamespace het, kan jy handelinge uitvoer wat tipies hierdie vaardigheid vereis, soos die koppel van lêersisteme, maar slegs binne die konteks van jou gebruikersnamespace. Enige handelinge wat jy met hierdie vaardigheid uitvoer, sal nie die gasheerstelsel of ander namespaces beïnvloed nie.

{% hint style="warning" %}
Daarom, selfs al sal die verkryging van 'n nuwe proses binne 'n nuwe gebruikersnamespace **alle vaardighede teruggee** (CapEff: 000001ffffffffff), kan jy eintlik **slegs diegene wat verband hou met die namespace** gebruik (soos die koppel van lêers byvoorbeeld), maar nie almal nie. Dus is dit op sigself nie genoeg om uit 'n Docker-houer te ontsnap nie.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
```
## Verwysings
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
