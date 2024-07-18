# Almacenamiento en la Nube Local

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) para construir y **automatizar flujos de trabajo** fácilmente impulsados por las **herramientas comunitarias más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

En Windows, puedes encontrar la carpeta de OneDrive en `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Y dentro de `logs\Personal` es posible encontrar el archivo `SyncDiagnostics.log` que contiene algunos datos interesantes sobre los archivos sincronizados:

* Tamaño en bytes
* Fecha de creación
* Fecha de modificación
* Número de archivos en la nube
* Número de archivos en la carpeta
* **CID**: ID único del usuario de OneDrive
* Hora de generación del informe
* Tamaño del HD del sistema operativo

Una vez que hayas encontrado el CID, se recomienda **buscar archivos que contengan este ID**. Es posible que encuentres archivos con el nombre: _**\<CID>.ini**_ y _**\<CID>.dat**_ que pueden contener información interesante como los nombres de los archivos sincronizados con OneDrive.

## Google Drive

En Windows, puedes encontrar la carpeta principal de Google Drive en `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Esta carpeta contiene un archivo llamado Sync\_log.log con información como la dirección de correo electrónico de la cuenta, nombres de archivos, marcas de tiempo, hashes MD5 de los archivos, etc. Incluso los archivos eliminados aparecen en ese archivo de registro con su correspondiente MD5.

El archivo **`Cloud_graph\Cloud_graph.db`** es una base de datos sqlite que contiene la tabla **`cloud_graph_entry`**. En esta tabla puedes encontrar el **nombre** de los **archivos sincronizados**, tiempo de modificación, tamaño y el checksum MD5 de los archivos.

Los datos de la tabla de la base de datos **`Sync_config.db`** contienen la dirección de correo electrónico de la cuenta, la ruta de las carpetas compartidas y la versión de Google Drive.

## Dropbox

Dropbox utiliza **bases de datos SQLite** para gestionar los archivos. En este\
Puedes encontrar las bases de datos en las carpetas:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

Y las bases de datos principales son:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

La extensión ".dbx" significa que las **bases de datos** están **encriptadas**. Dropbox utiliza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Para entender mejor la encriptación que utiliza Dropbox, puedes leer [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Sin embargo, la información principal es:

* **Entropía**: d114a55212655f74bd772e37e64aee9b
* **Sal**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritmo**: PBKDF2
* **Iteraciones**: 1066

Aparte de esa información, para desencriptar las bases de datos aún necesitas:

* La **clave DPAPI encriptada**: Puedes encontrarla en el registro dentro de `NTUSER.DAT\Software\Dropbox\ks\client` (exporta estos datos como binarios)
* Los **hives** de **`SYSTEM`** y **`SECURITY`**
* Las **claves maestras DPAPI**: Que se pueden encontrar en `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* El **nombre de usuario** y **contraseña** del usuario de Windows

Luego puedes usar la herramienta [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Si todo sale como se espera, la herramienta indicará la **clave primaria** que necesitas **usar para recuperar la original**. Para recuperar la original, simplemente usa esta [receta de cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) poniendo la clave primaria como la "frase de paso" dentro de la receta.

El hex resultante es la clave final utilizada para encriptar las bases de datos que se puede desencriptar con:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
El **`config.dbx`** base de datos contiene:

* **Email**: El correo electrónico del usuario
* **usernamedisplayname**: El nombre del usuario
* **dropbox\_path**: Ruta donde se encuentra la carpeta de Dropbox
* **Host\_id: Hash** utilizado para autenticar en la nube. Esto solo se puede revocar desde la web.
* **Root\_ns**: Identificador del usuario

La **`filecache.db`** base de datos contiene información sobre todos los archivos y carpetas sincronizados con Dropbox. La tabla `File_journal` es la que tiene más información útil:

* **Server\_path**: Ruta donde se encuentra el archivo dentro del servidor (esta ruta está precedida por el `host_id` del cliente).
* **local\_sjid**: Versión del archivo
* **local\_mtime**: Fecha de modificación
* **local\_ctime**: Fecha de creación

Otras tablas dentro de esta base de datos contienen información más interesante:

* **block\_cache**: hash de todos los archivos y carpetas de Dropbox
* **block\_ref**: Relaciona el ID de hash de la tabla `block_cache` con el ID del archivo en la tabla `file_journal`
* **mount\_table**: Carpetas compartidas de Dropbox
* **deleted\_fields**: Archivos eliminados de Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) para construir y **automatizar flujos de trabajo** fácilmente impulsados por las **herramientas comunitarias más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
