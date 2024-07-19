# AD CS Certificate Theft

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

**Este es un pequeño resumen de los capítulos de Robo de la increíble investigación de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Qué puedo hacer con un certificado

Antes de verificar cómo robar los certificados, aquí tienes algo de información sobre cómo encontrar para qué es útil el certificado:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportando Certificados Usando las API Crypto – THEFT1

En una **sesión de escritorio interactiva**, extraer un certificado de usuario o de máquina, junto con la clave privada, se puede hacer fácilmente, particularmente si la **clave privada es exportable**. Esto se puede lograr navegando al certificado en `certmgr.msc`, haciendo clic derecho sobre él y seleccionando `All Tasks → Export` para generar un archivo .pfx protegido por contraseña.

Para un **enfoque programático**, están disponibles herramientas como el cmdlet de PowerShell `ExportPfxCertificate` o proyectos como [el proyecto CertStealer C# de TheWover](https://github.com/TheWover/CertStealer). Estos utilizan la **Microsoft CryptoAPI** (CAPI) o la Cryptography API: Next Generation (CNG) para interactuar con el almacén de certificados. Estas API proporcionan una gama de servicios criptográficos, incluidos los necesarios para el almacenamiento y la autenticación de certificados.

Sin embargo, si una clave privada está configurada como no exportable, tanto CAPI como CNG normalmente bloquearán la extracción de tales certificados. Para eludir esta restricción, se pueden emplear herramientas como **Mimikatz**. Mimikatz ofrece comandos `crypto::capi` y `crypto::cng` para parchear las respectivas API, permitiendo la exportación de claves privadas. Específicamente, `crypto::capi` parchea el CAPI dentro del proceso actual, mientras que `crypto::cng` apunta a la memoria de **lsass.exe** para el parcheo.

## Robo de Certificados de Usuario a través de DPAPI – THEFT2

Más información sobre DPAPI en:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

En Windows, **las claves privadas de los certificados están protegidas por DPAPI**. Es crucial reconocer que las **ubicaciones de almacenamiento para las claves privadas de usuario y de máquina** son distintas, y las estructuras de archivos varían dependiendo de la API criptográfica utilizada por el sistema operativo. **SharpDPAPI** es una herramienta que puede navegar estas diferencias automáticamente al descifrar los blobs de DPAPI.

**Los certificados de usuario** se encuentran predominantemente en el registro bajo `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, pero algunos también se pueden encontrar en el directorio `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Las correspondientes **claves privadas** para estos certificados se almacenan típicamente en `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para claves **CAPI** y `%APPDATA%\Microsoft\Crypto\Keys\` para claves **CNG**.

Para **extraer un certificado y su clave privada asociada**, el proceso implica:

1. **Seleccionar el certificado objetivo** del almacén del usuario y recuperar su nombre de almacén de claves.
2. **Localizar la masterkey de DPAPI requerida** para descifrar la clave privada correspondiente.
3. **Descifrar la clave privada** utilizando la masterkey de DPAPI en texto plano.

Para **adquirir la masterkey de DPAPI en texto plano**, se pueden utilizar los siguientes enfoques:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para agilizar la descifrado de archivos de masterkey y archivos de clave privada, el comando `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) resulta beneficioso. Acepta `/pvk`, `/mkfile`, `/password` o `{GUID}:KEY` como argumentos para descifrar las claves privadas y los certificados vinculados, generando posteriormente un archivo `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Robo de Certificados de Máquina a través de DPAPI – THEFT3

Los certificados de máquina almacenados por Windows en el registro en `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` y las claves privadas asociadas ubicadas en `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (para CAPI) y `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (para CNG) están encriptados utilizando las claves maestras DPAPI de la máquina. Estas claves no pueden ser desencriptadas con la clave de respaldo DPAPI del dominio; en su lugar, se requiere el **secreto LSA DPAPI_SYSTEM**, al que solo el usuario SYSTEM puede acceder.

La desencriptación manual se puede lograr ejecutando el comando `lsadump::secrets` en **Mimikatz** para extraer el secreto LSA DPAPI_SYSTEM, y posteriormente utilizando esta clave para desencriptar las claves maestras de la máquina. Alternativamente, se puede usar el comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` de Mimikatz después de parchear CAPI/CNG como se describió anteriormente.

**SharpDPAPI** ofrece un enfoque más automatizado con su comando de certificados. Cuando se utiliza la bandera `/machine` con permisos elevados, se eleva a SYSTEM, volcando el secreto LSA DPAPI_SYSTEM, lo utiliza para desencriptar las claves maestras DPAPI de la máquina y luego emplea estas claves en texto plano como una tabla de búsqueda para desencriptar cualquier clave privada de certificado de máquina.


## Encontrando Archivos de Certificados – THEFT4

Los certificados a veces se encuentran directamente dentro del sistema de archivos, como en comparticiones de archivos o en la carpeta de Descargas. Los tipos de archivos de certificados más comúnmente encontrados dirigidos a entornos de Windows son los archivos `.pfx` y `.p12`. Aunque con menos frecuencia, también aparecen archivos con extensiones `.pkcs12` y `.pem`. Otras extensiones de archivo relacionadas con certificados que son notables incluyen:
- `.key` para claves privadas,
- `.crt`/`.cer` solo para certificados,
- `.csr` para Solicitudes de Firma de Certificado, que no contienen certificados ni claves privadas,
- `.jks`/`.keystore`/`.keys` para Almacenes de Claves de Java, que pueden contener certificados junto con claves privadas utilizadas por aplicaciones Java.

Estos archivos se pueden buscar utilizando PowerShell o el símbolo del sistema buscando las extensiones mencionadas.

En casos donde se encuentra un archivo de certificado PKCS#12 y está protegido por una contraseña, la extracción de un hash es posible mediante el uso de `pfx2john.py`, disponible en [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Posteriormente, se puede emplear JohnTheRipper para intentar descifrar la contraseña.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

El contenido dado explica un método para el robo de credenciales NTLM a través de PKINIT, específicamente mediante el método de robo etiquetado como THEFT5. Aquí hay una reexplicación en voz pasiva, con el contenido anonimizado y resumido donde sea aplicable:

Para soportar la autenticación NTLM [MS-NLMP] para aplicaciones que no facilitan la autenticación Kerberos, se diseñó el KDC para devolver la función unidireccional (OWF) NTLM del usuario dentro del certificado de atributo de privilegio (PAC), específicamente en el búfer `PAC_CREDENTIAL_INFO`, cuando se utiliza PKCA. En consecuencia, si una cuenta se autentica y asegura un Ticket-Granting Ticket (TGT) a través de PKINIT, se proporciona inherentemente un mecanismo que permite al host actual extraer el hash NTLM del TGT para mantener los protocolos de autenticación heredados. Este proceso implica la decripción de la estructura `PAC_CREDENTIAL_DATA`, que es esencialmente una representación serializada NDR del texto plano NTLM.

La utilidad **Kekeo**, accesible en [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), se menciona como capaz de solicitar un TGT que contenga estos datos específicos, facilitando así la recuperación del NTLM del usuario. El comando utilizado para este propósito es el siguiente:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Además, se señala que Kekeo puede procesar certificados protegidos por tarjeta inteligente, dado que se puede recuperar el pin, haciendo referencia a [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). La misma capacidad se indica que es soportada por **Rubeus**, disponible en [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Esta explicación encapsula el proceso y las herramientas involucradas en el robo de credenciales NTLM a través de PKINIT, centrándose en la recuperación de hashes NTLM a través de TGT obtenidos usando PKINIT, y las utilidades que facilitan este proceso.

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
