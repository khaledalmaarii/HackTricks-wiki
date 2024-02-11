# Uhifadhi wa Wingu wa Ndani

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** kwa kutumia zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Katika Windows, unaweza kupata folda ya OneDrive katika `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Na ndani ya `logs\Personal` inawezekana kupata faili ya `SyncDiagnostics.log` ambayo ina data ya kuvutia kuhusu faili zilizosawazishwa:

* Ukubwa kwa herufi
* Tarehe ya kuundwa
* Tarehe ya kubadilishwa
* Idadi ya faili kwenye wingu
* Idadi ya faili kwenye folda
* **CID**: Kitambulisho cha kipekee cha mtumiaji wa OneDrive
* Wakati wa kuzalisha ripoti
* Ukubwa wa HD ya OS

Marafiki umepata CID inashauriwa **kutafuta faili zinazotumia kitambulisho hiki**. Unaweza kupata faili zenye jina: _**\<CID>.ini**_ na _**\<CID>.dat**_ ambazo zinaweza kuwa na habari ya kuvutia kama majina ya faili zilizosawazishwa na OneDrive.

## Google Drive

Katika Windows, unaweza kupata folda kuu ya Google Drive katika `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Folda hii ina faili inayoitwa Sync\_log.log na habari kama anwani ya barua pepe ya akaunti, majina ya faili, alama za wakati, hashi za MD5 za faili, nk. Hata faili zilizofutwa zinaonekana kwenye faili hiyo ya kumbukumbu na hashi zao za MD5 zinazofanana.

Faili **`Cloud_graph\Cloud_graph.db`** ni database ya sqlite ambayo ina meza **`cloud_graph_entry`**. Katika meza hii unaweza kupata **jina** la **faili zilizosawazishwa**, wakati uliobadilishwa, ukubwa, na hashi ya MD5 ya faili.

Data ya meza ya database **`Sync_config.db`** ina anwani ya barua pepe ya akaunti, njia ya folda zilizoshirikiwa, na toleo la Google Drive.

## Dropbox

Dropbox hutumia **databases za SQLite** kusimamia faili. Katika\
Unaweza kupata databases katika folda:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

Na databases kuu ni:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Kifungu cha ".dbx" kinamaanisha kuwa **databases** zime **fichwa**. Dropbox hutumia **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Ili kuelewa vizuri encryption ambayo Dropbox hutumia unaweza kusoma [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Walakini, habari kuu ni:

* **Entropy**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algorithm**: PBKDF2
* **Iterations**: 1066

Mbali na habari hiyo, ili kufichua databases bado unahitaji:

* **DPAPI key iliyofichwa**: Unaweza kuipata kwenye usajili ndani ya `NTUSER.DAT\Software\Dropbox\ks\client` (tuma data hii kama binary)
* **`SYSTEM`** na **`SECURITY`** hives
* **DPAPI master keys**: Ambazo zinaweza kupatikana katika `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* **jina la mtumiaji** na **nywila** ya mtumiaji wa Windows

Kisha unaweza kutumia zana [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

Ikiwa kila kitu kinaenda kama ilivyotarajiwa, zana itaonyesha **funguo kuu** ambayo unahitaji **kutumia kurejesha ile halisi**. Ili kurejesha ile halisi, tumia [cyber\_chef receipt](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) weka funguo kuu kama "passphrase" ndani ya risiti.

Hex inayopatikana ndiyo funguo ya mwisho inayotumiwa kuficha databases ambayo inaweza kufichuliwa na:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** database ina:

* **Barua pepe**: Barua pepe ya mtumiaji
* **usernamedisplayname**: Jina la mtumiaji
* **dropbox\_path**: Njia ambapo folda ya Dropbox iko
* **Host\_id: Hash**: Hutumiwa kuthibitisha kitambulisho cha wingu. Hii inaweza kufutwa tu kutoka kwenye wavuti.
* **Root\_ns**: Kitambulisho cha mtumiaji

**`filecache.db`** database ina habari kuhusu faili na folda zote zilizosawazishwa na Dropbox. Jedwali la `File_journal` ndilo lenye habari muhimu zaidi:

* **Server\_path**: Njia ambapo faili iko ndani ya seva (njia hii inaongozwa na `host_id` ya mteja).
* **local\_sjid**: Toleo la faili
* **local\_mtime**: Tarehe ya kubadilisha
* **local\_ctime**: Tarehe ya kuundwa

Jedwali zingine ndani ya hii database zina habari zaidi ya kuvutia:

* **block\_cache**: hash ya faili na folda zote za Dropbox
* **block\_ref**: Inahusisha kitambulisho cha hash ya jedwali la `block_cache` na kitambulisho cha faili katika jedwali la `file_journal`
* **mount\_table**: Folders za kushiriki za Dropbox
* **deleted\_fields**: Faili zilizofutwa za Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na kutekeleza kwa urahisi **mchakato wa kiotomatiki** ulioendeshwa na zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
