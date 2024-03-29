# Uhifadhi wa Wingu wa Kienyeji

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa kutumia zana za **jamii ya juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Katika Windows, unaweza kupata folda ya OneDrive katika `\Users\<jina la mtumiaji>\AppData\Local\Microsoft\OneDrive`. Na ndani ya `logs\Personal` inawezekana kupata faili ya `SyncDiagnostics.log` ambayo ina data ya kuvutia kuhusu faili zilizosawazishwa:

* Ukubwa kwa bayti
* Tarehe ya uundaji
* Tarehe ya marekebisho
* Idadi ya faili kwenye wingu
* Idadi ya faili kwenye folda
* **CID**: Kitambulisho cha kipekee cha mtumiaji wa OneDrive
* Wakati wa kuzalisha ripoti
* Ukubwa wa HD ya OS

Marafiki unapopata CID inapendekezwa **tafuta faili zinazoleta kitambulisho hiki**. Unaweza kupata faili zenye jina: _**\<CID>.ini**_ na _**\<CID>.dat**_ ambazo zinaweza kuwa na habari ya kuvutia kama majina ya faili zilizosawazishwa na OneDrive.

## Google Drive

Katika Windows, unaweza kupata folda kuu ya Google Drive katika `\Users\<jina la mtumiaji>\AppData\Local\Google\Drive\user_default`\
Folda hii ina faili inayoitwa Sync\_log.log na habari kama anwani ya barua pepe ya akaunti, majina ya faili, alama za wakati, hashi za MD5 za faili, n.k. Hata faili zilizofutwa zinaonekana kwenye faili hiyo ya logi pamoja na hashi zake za MD5 zinazofanana.

Faili **`Cloud_graph\Cloud_graph.db`** ni database ya sqlite ambayo ina meza **`cloud_graph_entry`**. Katika meza hii unaweza kupata **jina** la **faili zilizosawazishwa**, wakati uliobadilishwa, ukubwa, na hashi ya MD5 ya faili.

Data ya meza ya database ya **`Sync_config.db`** ina anwani ya barua pepe ya akaunti, njia ya folda zilizoshirikiwa na toleo la Google Drive.

## Dropbox

Dropbox hutumia **databases za SQLite** kusimamia faili. Katika\
Unaweza kupata databases katika folda:

* `\Users\<jina la mtumiaji>\AppData\Local\Dropbox`
* `\Users\<jina la mtumiaji>\AppData\Local\Dropbox\Instance1`
* `\Users\<jina la mtumiaji>\AppData\Roaming\Dropbox`

Na databases kuu ni:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Kificho cha ".dbx" kina maana kwamba **databases** zime **fichwa**. Dropbox hutumia **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Kuelewa vizuri zaidi ujazo ambao Dropbox hutumia unaweza kusoma [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Walakini, habari kuu ni:

* **Entropy**: d114a55212655f74bd772e37e64aee9b
* **Chumvi**: 0D638C092E8B82FC452883F95F355B8E
* **Algorithimu**: PBKDF2
* **Mizunguko**: 1066

Isipokuwa habari hiyo, kwa kufichua databases bado unahitaji:

* **Funguo iliyofichwa ya DPAPI**: Unaweza kuipata kwenye usajili ndani ya `NTUSER.DAT\Software\Dropbox\ks\client` (tolea data hii kama binary)
* **`SYSTEM`** na **`SECURITY`** hives
* **Funguo za msingi za DPAPI**: Ambazo zinaweza kupatikana katika `\Users\<jina la mtumiaji>\AppData\Roaming\Microsoft\Protect`
* **jina la mtumiaji** na **nywila** ya mtumiaji wa Windows

Kisha unaweza kutumia zana [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

Ikiwa kila kitu kinaenda kama ilivyotarajiwa, zana itaonyesha **funguo kuu** ambao unahitaji **kutumia kurejesha ile ya asili**. Ili kurejesha ile ya asili, tumia hii [cyber\_chef receipt](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\) ukiweka funguo kuu kama "neno la siri" ndani ya risiti.

Hex inayopatikana ndio funguo la mwisho linalotumiwa kufichua databases ambayo inaweza kufichuliwa na:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** database ina:

- **Barua pepe**: Barua pepe ya mtumiaji
- **usernamedisplayname**: Jina la mtumiaji
- **dropbox\_path**: Njia ambapo folda ya dropbox ipo
- **Host\_id: Hash** hutumiwa kuthibitisha kwa wingu. Hii inaweza kufutwa tu kutoka kwenye wavuti.
- **Root\_ns**: Kitambulisho cha mtumiaji

**`filecache.db`** database ina taarifa kuhusu faili na folda zote zilizosawazishwa na Dropbox. Jedwali `File_journal` ndio lenye taarifa muhimu zaidi:

- **Server\_path**: Njia ambapo faili ipo kwenye seva (njia hii inaanzwa na `host_id` ya mteja).
- **local\_sjid**: Toleo la faili
- **local\_mtime**: Tarehe ya marekebisho
- **local\_ctime**: Tarehe ya uundaji

Vidokezo vingine ndani ya hii database vina taarifa zaidi ya kuvutia:

- **block\_cache**: hash ya faili na folda zote za Dropbox
- **block\_ref**: Inahusisha kitambulisho cha hash ya jedwali `block_cache` na kitambulisho cha faili katika jedwali `file_journal`
- **mount\_table**: Shiriki folda za Dropbox
- **deleted\_fields**: Faili zilizofutwa za Dropbox
- **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa urahisi ikiwa na zana za jamii za **juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

- Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
- Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
- Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
- **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
- **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
