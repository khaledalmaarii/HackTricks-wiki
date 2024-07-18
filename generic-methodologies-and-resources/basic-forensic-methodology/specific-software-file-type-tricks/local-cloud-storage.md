# Hifadhi ya Wingu la Mitaa

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) kujenga na **kujiendesha** kwa urahisi kwa kutumia zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

Katika Windows, unaweza kupata folda ya OneDrive katika `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Na ndani ya `logs\Personal` inawezekana kupata faili `SyncDiagnostics.log` ambayo ina data za kuvutia kuhusu faili zilizohusishwa:

* Ukubwa kwa bytes
* Tarehe ya kuundwa
* Tarehe ya mabadiliko
* Idadi ya faili katika wingu
* Idadi ya faili katika folda
* **CID**: Kitambulisho cha kipekee cha mtumiaji wa OneDrive
* Wakati wa kuzalisha ripoti
* Ukubwa wa HD wa OS

Mara tu unapopata CID inashauriwa **kutafuta faili zinazohusisha ID hii**. Unaweza kupata faili zenye jina: _**\<CID>.ini**_ na _**\<CID>.dat**_ ambazo zinaweza kuwa na taarifa za kuvutia kama majina ya faili zilizohusishwa na OneDrive.

## Google Drive

Katika Windows, unaweza kupata folda kuu ya Google Drive katika `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Folda hii ina faili inayoitwa Sync\_log.log yenye taarifa kama anwani ya barua pepe ya akaunti, majina ya faili, alama za wakati, MD5 hashes za faili, nk. Hata faili zilizofutwa zinaonekana katika faili hiyo ya logi na MD5 inayohusiana.

Faili **`Cloud_graph\Cloud_graph.db`** ni database ya sqlite ambayo ina jedwali **`cloud_graph_entry`**. Katika jedwali hili unaweza kupata **jina** la **faili zilizohusishwa**, wakati wa mabadiliko, ukubwa, na MD5 checksum za faili.

Data za jedwali la database **`Sync_config.db`** zina anwani ya barua pepe ya akaunti, njia za folda zilizoshirikiwa na toleo la Google Drive.

## Dropbox

Dropbox hutumia **databases za SQLite** kusimamia faili. Katika hii\
Unaweza kupata databases katika folda:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

Na databases kuu ni:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Kiambatisho ".dbx" kinamaanisha kwamba **databases** zime **siri**. Dropbox hutumia **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Ili kuelewa vizuri zaidi usimbuaji ambao Dropbox hutumia unaweza kusoma [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Hata hivyo, taarifa kuu ni:

* **Entropy**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algorithm**: PBKDF2
* **Iterations**: 1066

Mbali na taarifa hiyo, ili kufungua databases bado unahitaji:

* **funguo ya DPAPI iliyosimbwa**: Unaweza kuipata katika rejista ndani ya `NTUSER.DAT\Software\Dropbox\ks\client` (safisha data hii kama binary)
* **`SYSTEM`** na **`SECURITY`** hives
* **funguo kuu za DPAPI**: Ambazo zinaweza kupatikana katika `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* **jina la mtumiaji** na **nenosiri** la mtumiaji wa Windows

Kisha unaweza kutumia chombo [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Ikiwa kila kitu kinaenda kama inavyotarajiwa, chombo kitakuonyesha **funguo kuu** ambayo unahitaji **kutumia ili kurejesha ile ya awali**. Ili kurejesha ile ya awali, tumia [mapishi haya ya cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) ukitumia funguo kuu kama "passphrase" ndani ya mapishi.

Hex inayotokana ni funguo ya mwisho inayotumika kusimbua databases ambazo zinaweza kufunguliwa na:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** database contains:

* **Email**: Barua pepe ya mtumiaji
* **usernamedisplayname**: Jina la mtumiaji
* **dropbox\_path**: Njia ambapo folda ya dropbox iko
* **Host\_id: Hash** inayotumika kuthibitisha kwenye wingu. Hii inaweza kufutwa tu kutoka kwenye wavuti.
* **Root\_ns**: Kitambulisho cha mtumiaji

The **`filecache.db`** database contains information about all the files and folders synchronized with Dropbox. The table `File_journal` is the one with more useful information:

* **Server\_path**: Njia ambapo faili iko ndani ya seva (njia hii inatanguliwa na `host_id` ya mteja).
* **local\_sjid**: Toleo la faili
* **local\_mtime**: Tarehe ya mabadiliko
* **local\_ctime**: Tarehe ya kuunda

Other tables inside this database contain more interesting information:

* **block\_cache**: hash ya faili zote na folda za Dropbox
* **block\_ref**: Inahusisha kitambulisho cha hash cha jedwali `block_cache` na kitambulisho cha faili katika jedwali `file_journal`
* **mount\_table**: Shiriki folda za dropbox
* **deleted\_fields**: Faili zilizofutwa za Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
