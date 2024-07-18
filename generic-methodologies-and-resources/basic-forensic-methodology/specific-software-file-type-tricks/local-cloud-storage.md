# Yerel Bulut Depolama

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

Windows'ta, OneDrive klasörünü `\Users\<kullanıcı_adı>\AppData\Local\Microsoft\OneDrive` içinde bulabilirsiniz. Ve `logs\Personal` içinde, senkronize edilmiş dosyalarla ilgili bazı ilginç verileri içeren `SyncDiagnostics.log` dosyasını bulmak mümkündür:

* Boyut (bayt cinsinden)
* Oluşturulma tarihi
* Değiştirilme tarihi
* Bulutta bulunan dosya sayısı
* Klasörde bulunan dosya sayısı
* **CID**: OneDrive kullanıcısının benzersiz kimliği
* Rapor oluşturma zamanı
* İşletim sisteminin HD boyutu

CID'yi bulduktan sonra, **bu kimliği içeren dosyaları aramanız önerilir**. OneDrive ile senkronize edilmiş dosyaların adlarını içerebilecek _**\<CID>.ini**_ ve _**\<CID>.dat**_ adında dosyalar bulabilirsiniz.

## Google Drive

Windows'ta, ana Google Drive klasörünü `\Users\<kullanıcı_adı>\AppData\Local\Google\Drive\user_default` içinde bulabilirsiniz.\
Bu klasör, hesap e-posta adresi, dosya adları, zaman damgaları, dosyaların MD5 hash'leri gibi bilgileri içeren Sync\_log.log adında bir dosya içerir. Silinmiş dosyalar bile bu günlük dosyasında ilgili MD5 ile görünür.

**`Cloud_graph\Cloud_graph.db`** dosyası, **`cloud_graph_entry`** tablosunu içeren bir sqlite veritabanıdır. Bu tabloda, **senkronize** **dosyaların** **adını**, değiştirilme zamanını, boyutunu ve dosyaların MD5 kontrol toplamını bulabilirsiniz.

**`Sync_config.db`** veritabanının tablo verileri, hesap e-posta adresini, paylaşılan klasörlerin yolunu ve Google Drive sürümünü içerir.

## Dropbox

Dropbox, dosyaları yönetmek için **SQLite veritabanları** kullanır. Bu\
Veritabanlarını şu klasörlerde bulabilirsiniz:

* `\Users\<kullanıcı_adı>\AppData\Local\Dropbox`
* `\Users\<kullanıcı_adı>\AppData\Local\Dropbox\Instance1`
* `\Users\<kullanıcı_adı>\AppData\Roaming\Dropbox`

Ve ana veritabanları şunlardır:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx" uzantısı, **veritabanlarının** **şifreli** olduğunu gösterir. Dropbox, **DPAPI** kullanır ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Dropbox'un kullandığı şifrelemeyi daha iyi anlamak için [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) adresini okuyabilirsiniz.

Ancak, ana bilgiler şunlardır:

* **Entropy**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritma**: PBKDF2
* **İterasyonlar**: 1066

Bu bilgilere ek olarak, veritabanlarını şifrelerini çözmek için hala şunlara ihtiyacınız var:

* **şifrelenmiş DPAPI anahtarı**: Bunu `NTUSER.DAT\Software\Dropbox\ks\client` içinde kayıt defterinde bulabilirsiniz (bu veriyi ikili olarak dışa aktarın)
* **`SYSTEM`** ve **`SECURITY`** hives
* **DPAPI anahtarları**: `\Users\<kullanıcı_adı>\AppData\Roaming\Microsoft\Protect` içinde bulunabilir
* Windows kullanıcısının **kullanıcı adı** ve **şifresi**

Sonra [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)** aracını kullanabilirsiniz:**

![](<../../../.gitbook/assets/image (443).png>)

Her şey beklendiği gibi giderse, araç, **orijinalini geri kazanmak için kullanmanız gereken** **anahtar**'ı gösterecektir. Orijinalini geri kazanmak için, bu [cyber\_chef tarifi](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) kullanarak anahtarı "şifre" olarak tarifin içine koyun.

Elde edilen hex, veritabanlarını şifrelemek için kullanılan son anahtardır ve şu şekilde şifresi çözülebilir:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** veritabanı şunları içerir:

* **Email**: Kullanıcının e-posta adresi
* **usernamedisplayname**: Kullanıcının adı
* **dropbox\_path**: Dropbox klasörünün bulunduğu yol
* **Host\_id: Hash** buluta kimlik doğrulamak için kullanılır. Bu yalnızca web üzerinden iptal edilebilir.
* **Root\_ns**: Kullanıcı tanımlayıcısı

The **`filecache.db`** veritabanı, Dropbox ile senkronize edilen tüm dosyalar ve klasörler hakkında bilgi içerir. `File_journal` tablosu daha fazla yararlı bilgiye sahiptir:

* **Server\_path**: Dosyanın sunucu içindeki bulunduğu yol (bu yol, istemcinin `host_id` ile önceden gelir).
* **local\_sjid**: Dosyanın versiyonu
* **local\_mtime**: Değiştirilme tarihi
* **local\_ctime**: Oluşturulma tarihi

Bu veritabanındaki diğer tablolar daha ilginç bilgiler içerir:

* **block\_cache**: Dropbox'ın tüm dosya ve klasörlerinin hash'i
* **block\_ref**: `block_cache` tablosunun hash ID'sini `file_journal` tablosundaki dosya ID'si ile ilişkilendirir
* **mount\_table**: Dropbox'ın paylaşılan klasörleri
* **deleted\_fields**: Dropbox'tan silinmiş dosyalar
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
