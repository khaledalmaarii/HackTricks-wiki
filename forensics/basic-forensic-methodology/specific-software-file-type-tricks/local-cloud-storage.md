# Yerel Bulut Depolama

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) göz atın
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Windows'ta, OneDrive klasörünü `\Users\<kullanıcıadı>\AppData\Local\Microsoft\OneDrive` dizininde bulabilirsiniz. Ve içinde `logs\Personal` klasöründe senkronize edilen dosyalarla ilgili bazı ilginç veriler içeren `SyncDiagnostics.log` dosyasını bulmak mümkündür:

* Bayt cinsinden boyut
* Oluşturma tarihi
* Değiştirme tarihi
* Bulutta bulunan dosyaların sayısı
* Klasörde bulunan dosyaların sayısı
* **CID**: OneDrive kullanıcısının benzersiz kimliği
* Rapor oluşturma zamanı
* İşletim sistemi HD'nin boyutu

CID'yi bulduktan sonra, bu kimliği içeren dosyaları **aramanız önerilir**. OneDrive ile senkronize edilen dosyaların adlarını içeren _**\<CID>.ini**_ ve _**\<CID>.dat**_ adında dosyalar bulabilirsiniz.

## Google Drive

Windows'ta, ana Google Drive klasörünü `\Users\<kullanıcıadı>\AppData\Local\Google\Drive\user_default` dizininde bulabilirsiniz.\
Bu klasör, hesabın e-posta adresi, dosya adları, zaman damgaları, dosyaların MD5 karma değerleri vb. gibi bilgileri içeren Sync\_log.log adlı bir dosya içerir. Silinen dosyalar bile ilgili MD5 ile birlikte bu günlük dosyasında görünür.

**`Cloud_graph\Cloud_graph.db`** dosyası, **`cloud_graph_entry`** tablosunu içeren bir sqlite veritabanıdır. Bu tabloda senkronize edilen dosyaların **adı**, **değiştirilme zamanı**, **boyutu** ve **MD5 karma değeri** bulunabilir.

Veritabanının **`Sync_config.db`** tablo verileri, hesabın e-posta adresini, paylaşılan klasörlerin yolunu ve Google Drive sürümünü içerir.

## Dropbox

Dropbox, dosyaları yönetmek için **SQLite veritabanlarını** kullanır. Bu\
Veritabanlarını şu klasörlerde bulabilirsiniz:

* `\Users\<kullanıcıadı>\AppData\Local\Dropbox`
* `\Users\<kullanıcıadı>\AppData\Local\Dropbox\Instance1`
* `\Users\<kullanıcıadı>\AppData\Roaming\Dropbox`

Ve ana veritabanaları şunlardır:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx" uzantısı, veritabanlarının **şifrelendiği** anlamına gelir. Dropbox, **DPAPI** kullanır ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Dropbox'un kullandığı şifrelemeyi daha iyi anlamak için [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) adresini okuyabilirsiniz.

Ancak, temel bilgiler şunlardır:

* **Entropy**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritma**: PBKDF2
* **İterasyonlar**: 1066

Bu bilgilerin yanı sıra, veritabanlarını şifrelemek için hala ihtiyacınız olanlar:

* **Şifrelenmiş DPAPI anahtarı**: Bu anahtarı, `NTUSER.DAT\Software\Dropbox\ks\client` içinde kayıt defterinde bulabilirsiniz (bu veriyi ikili olarak dışa aktarın)
* **`SYSTEM`** ve **`SECURITY`** hive'ları
* **DPAPI anahtarları**: Bunlar, `\Users\<kullanıcıadı>\AppData\Roaming\Microsoft\Protect` dizininde bulunabilir
* Windows kullanıcısının **kullanıcı adı** ve **parolası**

Ardından, [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**** aracını kullanabilirsiniz:

![](<../../../.gitbook/assets/image (448).png>)

Her şey beklenildiği gibi giderse, araç, orijinali kurtarmak için gereken **birincil anahtar**'ı gösterecektir. Orijinali kurtarmak için, bu [cyber\_chef tarifini](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) kullanarak birincil anahtarı tarifin "parola" olarak kullanın.

Sonuçta elde edilen onaltılık, veritabanlarını şifrelemek için kullanılan son anahtardır ve şu şekilde şifrelenmiş veritabanları çözülebilir:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** veritabanı aşağıdakileri içerir:

- **Email**: Kullanıcının e-posta adresi
- **usernamedisplayname**: Kullanıcının adı
- **dropbox\_path**: Dropbox klasörünün bulunduğu yol
- **Host\_id: Bulutu doğrulamak için kullanılan hash**. Bu sadece web üzerinden iptal edilebilir.
- **Root\_ns**: Kullanıcı kimliği

**`filecache.db`** veritabanı, Dropbox ile senkronize edilen tüm dosya ve klasörlerle ilgili bilgileri içerir. `File_journal` tablosu daha fazla kullanışlı bilgi içerir:

- **Server\_path**: Dosyanın sunucu içinde bulunduğu yol (bu yol, istemcinin `host_id` ile öncelenir).
- **local\_sjid**: Dosyanın sürümü
- **local\_mtime**: Değiştirilme tarihi
- **local\_ctime**: Oluşturma tarihi

Bu veritabanının içindeki diğer tablolar daha ilginç bilgiler içerir:

- **block\_cache**: Dropbox'un tüm dosya ve klasörlerinin hash değeri
- **block\_ref**: `block_cache` tablosundaki hash ID'sini `file_journal` tablosundaki dosya ID'siyle ilişkilendirir
- **mount\_table**: Dropbox paylaşılan klasörler
- **deleted\_fields**: Dropbox silinmiş dosyaları
- **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

- Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
- [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
- Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
- 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
- Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>
