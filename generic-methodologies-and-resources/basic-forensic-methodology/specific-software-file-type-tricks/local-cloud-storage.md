# Yerel Bulut Depolama

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**] (https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**] (https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**] (https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**] (https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**] (https://github.com/carlospolop/hacktricks-cloud) github depolarına PR'lar gönderin.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**]'i kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Windows'ta, OneDrive klasörünü `\Users\<kullanıcıadı>\AppData\Local\Microsoft\OneDrive` içinde bulabilirsiniz. Ve içinde `logs\Personal` klasöründe senkronize edilen dosyalarla ilgili bazı ilginç veriler içeren `SyncDiagnostics.log` dosyasını bulmak mümkündür:

* Bayt cinsinden boyut
* Oluşturma tarihi
* Değiştirme tarihi
* Bulutta bulunan dosya sayısı
* Klasörde bulunan dosya sayısı
* **CID**: OneDrive kullanıcısının benzersiz kimliği
* Rapor oluşturma zamanı
* İşletim sisteminin HD boyutu

CID'yi bulduktan sonra **bu kimliği içeren dosyaları aramanız önerilir**. OneDrive ile senkronize edilen dosyaların adlarını içerebilecek _**\<CID>.ini**_ ve _**\<CID>.dat**_ adlı dosyaları bulabilirsiniz.

## Google Drive

Windows'ta, ana Google Drive klasörünü `\Users\<kullanıcıadı>\AppData\Local\Google\Drive\user_default` içinde bulabilirsiniz.\
Bu klasör, hesabın e-posta adresi, dosya adları, zaman damgaları, dosyaların MD5 karma değerleri vb. gibi bilgiler içeren Sync\_log.log adlı bir dosyayı içerir. Silinmiş dosyalar bile, ilgili MD5 değeriyle birlikte o log dosyasında görünür.

**`Cloud_graph\Cloud_graph.db`** dosyası, **`cloud_graph_entry`** tablosunu içeren bir sqlite veritabanıdır. Bu tabloda **senkronize edilen dosyaların adını**, değiştirilme zamanını, boyutunu ve dosyaların MD5 karma değerini bulabilirsiniz.

Veritabanının **`Sync_config.db`** tablo verileri hesabın e-posta adresini, paylaşılan klasörlerin yolunu ve Google Drive sürümünü içerir.

## Dropbox

Dropbox dosyaları yönetmek için **SQLite veritabanlarını** kullanır. Bu\
Veritabanlarını şu klasörlerde bulabilirsiniz:

* `\Users\<kullanıcıadı>\AppData\Local\Dropbox`
* `\Users\<kullanıcıadı>\AppData\Local\Dropbox\Instance1`
* `\Users\<kullanıcıadı>\AppData\Roaming\Dropbox`

Ve ana veritabanları şunlardır:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx" uzantısı, veritabanlarının **şifreli olduğu** anlamına gelir. Dropbox, **DPAPI**'yi kullanır ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Dropbox'un kullandığı şifrelemeyi daha iyi anlamak için [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) adresini okuyabilirsiniz.

Ancak, ana bilgiler şunlardır:

* **Entropi**: d114a55212655f74bd772e37e64aee9b
* **Tuz**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritma**: PBKDF2
* **İterasyonlar**: 1066

Bu bilgilerin yanı sıra, veritabanlarını şifrelemek için hala gerekenler:

* **Şifreli DPAPI anahtarı**: Bu anahtarı `NTUSER.DAT\Software\Dropbox\ks\client` içinde kayıt defterinde bulabilirsiniz (bu veriyi ikili olarak dışa aktarın)
* **`SYSTEM`** ve **`SECURITY`** hive'ları
* **DPAPI anahtarları**: Bunlar `\Users\<kullanıcıadı>\AppData\Roaming\Microsoft\Protect` içinde bulunabilir
* Windows kullanıcısının **kullanıcı adı** ve **şifresi**

Ardından [**DataProtectionDecryptor**] (https://nirsoft.net/utils/dpapi\_data\_decryptor.html)** aracını kullanabilirsiniz:**

![](<../../../.gitbook/assets/image (443).png>)

Her şey beklediğiniz gibi giderse, araç **kurtarmanız gereken birincil anahtarı** gösterecektir. Orijinal anahtarı kurtarmak için, bu [cyber\_chef reçetesini](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) alıntı içinde "parola" olarak birincil anahtarı koyun.

Sonuçta elde edilen onaltılık, veritabanlarını şifrelemek için kullanılan nihai anahtardır ve şununla şifrelenmiş veritabanlar şifresi çözülebilir:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** veritabanı şunları içerir:

- **Email**: Kullanıcının e-posta adresi
- **usernamedisplayname**: Kullanıcının adı
- **dropbox\_path**: Dropbox klasörünün bulunduğu yol
- **Host\_id**: Buluta kimlik doğrulamak için kullanılan hash. Bu sadece web üzerinden iptal edilebilir.
- **Root\_ns**: Kullanıcı kimliği

**`filecache.db`** veritabanı, Dropbox ile senkronize edilen tüm dosya ve klasörler hakkında bilgi içerir. En fazla kullanışlı bilgiye sahip olan tablo `File_journal`'dir:

- **Server\_path**: Sunucu içinde dosyanın bulunduğu yol (bu yol, istemcinin `host_id`'si tarafından önce gelir).
- **local\_sjid**: Dosyanın sürümü
- **local\_mtime**: Değiştirme tarihi
- **local\_ctime**: Oluşturma tarihi

Bu veritabanındaki diğer tablolar daha ilginç bilgiler içerir:

- **block\_cache**: Dropbox'un tüm dosya ve klasörlerinin hash'ı
- **block\_ref**: `block_cache` tablosundaki hash ID'sini `file_journal` tablosundaki dosya ID'si ile ilişkilendirir
- **mount\_table**: Dropbox'un paylaşılan klasörleri
- **deleted\_fields**: Silinen Dropbox dosyaları
- **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışları** oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

- **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
- [**Resmi PEASS & HackTricks ürünlerine göz atın**](https://peass.creator-spring.com)
- [**The PEASS Family'yi keşfedin**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
- 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**'da takip edin.**
- **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
