# AD CS Certificate Theft

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**This is a small summary of the Theft chapters of the awesome research from [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## What can I do with a certificate

Before checking how to steal the certificates here you have some info about how to find what the certificate is useful for:

---

## tlhIngan Hol Translation

# AD CS Certificate Theft

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>! </strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qaStaHvIS AWS hacking jatlhlaHbe'chugh</strong></a><strong>!</strong></summary>

HackTricks poH:

* **tlhIngan Hol HackTricks** 'e' vItlhutlh 'ej **HackTricks PDF** download **tlhIngan Hol HackTricks** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **qaStaHvIS**.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **ghItlh**.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **ghItlh**, **NFTs** [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **ghItlh**.
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group** [**tIq**](https://t.me/peass) **follow** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) **HackTricks Cloud** [**github repos**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)** **research** **awesome** **chapters** **Theft** **summary** **small** **is**


## What can I do with a certificate

**steal** **to how** **checking** **Before** **for useful is certificate the what find to how about info some have you here:

---
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
## Exporting Certificates Using the Crypto APIs – THEFT1

**Interactive desktop session**-Da, user yIbuS certificate, je machine certificate, je private key, DaH jatlhlaHbe'chugh, **private key exportable** DaH jatlhlaHbe'chugh, vaj certificate 'ej 'e' vItlhutlhlaH 'ej 'e' vItlhutlhlaH .pfx file password-protected vItlhutlh.

**Programmatic approach**-Da, PowerShell 'e' vItlhutlhlaH `ExportPfxCertificate` cmdlet, 'ej [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) project, vaj **Microsoft CryptoAPI** (CAPI) je Cryptography API: Next Generation (CNG) certificate store vItlhutlh 'ej authentication vItlhutlh. 

'ach, private key non-exportable DaH, CAPI je CNG normally extraction vItlhutlh. 'ach, **Mimikatz** vItlhutlhlaH tools vaj. Mimikatz 'e' vItlhutlhlaH `crypto::capi` je `crypto::cng` commands, CAPI je CNG patch vItlhutlh, private keys vItlhutlhlaH. 'e' vItlhutlhlaH `crypto::capi` CAPI vItlhutlhlaH current process, 'ej `crypto::cng` lsass.exe memory patch vItlhutlh.

## User Certificate Theft via DPAPI – THEFT2

DPAPI DaH jatlhlaHbe'chugh:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows DaH, **certificate private keys DPAPI** jatlhlaHbe'chugh. **User je machine private keys storage locations** DaH jatlhlaHbe'chugh, 'ej file structures vary operating system cryptographic API jatlhlaHbe'chugh. **SharpDPAPI** tool, DPAPI blobs decrypt vItlhutlh, automatically navigate jatlhlaHbe'chugh.

**User certificates** predominantly registry 'e' vItlhutlhlaH `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, 'ach 'oH certificates 'e' vItlhutlhlaH `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` directory vItlhutlh. 'e' vItlhutlhlaH **private keys** certificates typically stored `%APPDATA%\Microsoft\Crypto\RSA\User SID\` CAPI keys je `%APPDATA%\Microsoft\Crypto\Keys\` CNG keys vItlhutlh.

**Certificate je associated private key vItlhutlh**, process vItlhutlh involves:

1. **Selecting target certificate** user store 'ej retrieving key store name.
2. **Locating required DPAPI masterkey** corresponding private key decrypt vItlhutlh.
3. **Decrypting private key** plaintext DPAPI masterkey vItlhutlh.

**Plaintext DPAPI masterkey vItlhutlh**, approaches vItlhutlh:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
To'wI' jatlhqa'pu' 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Machine Certificate Theft via DPAPI – THEFT3

Windows registryDa HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificatesDa'wI' 'ej `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeysDa'wI' (CAPI) 'ej `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\KeysDa'wI' (CNG)Da'wI' jImejDa'wI' DPAPI master keysDa'wI' encrypt. 'ej 'oH 'e' vItlhutlhDPAPI backup keyDa'wI' decrypt; 'ach, **DPAPI_SYSTEM LSA secret**Da'wI' jImejDa'wI' SYSTEM userDa'wI' vItlhutlh.

Manual decryption vItlhutlhMimikatzDa'wI' `lsadump::secrets` commandDa'wI' jImejDa'wI' DPAPI_SYSTEM LSA secretDa'wI' extract, 'ej vItlhutlhDa'wI' jImejDa'wI' keyDa'wI' decrypt machine masterkeysDa'wI'. alternatively, MimikatzDa'wI' `crypto::certificates /export /systemstore:LOCAL_MACHINE` commandDa'wI' jImejDa'wI' CAPI/CNGDa'wI' patchDa'wI' vItlhutlh.

**SharpDPAPI**Da'wI' certificates commandDa'wI' vItlhutlhDa'wI' automated approachDa'wI'. `/machine` flagDa'wI' vItlhutlhDa'wI' elevated permissionsDa'wI' jImejDa'wI' SYSTEMDa'wI' vItlhutlhDa'wI' DPAPI_SYSTEM LSA secretDa'wI' extract, 'ej vItlhutlhDa'wI' jImejDa'wI' keyDa'wI' decrypt machine DPAPI masterkeysDa'wI'. 'ej 'oH plaintext keysDa'wI' lookup tableDa'wI' vItlhutlhDa'wI' decrypt machine certificate private keys.

## Finding Certificate Files – THEFT4

CertificatesDa'wI' directly filesystemDa'wI' jImejDa'wI' file sharesDa'wI' 'ej Downloads folderDa'wI'. WindowsDa'wI' targetDa'wI' certificate filesDa'wI' commonly encounteredDa'wI' `.pfx` 'ej `.p12` filesDa'wI'. 'ach, less frequentlyDa'wI', filesDa'wI' extensionsDa'wI' `.pkcs12` 'ej `.pem`Da'wI' appearDa'wI'. certificate-related file extensionsDa'wI' noteworthyDa'wI' include:
- `.key`Da'wI' private keysDa'wI',
- `.crt`/`.cer`Da'wI' certificatesDa'wI' only,
- `.csr`Da'wI' Certificate Signing RequestsDa'wI', certificatesDa'wI' private keysDa'wI' containDa'wI',
- `.jks`/`.keystore`/`.keys`Da'wI' Java KeystoresDa'wI', certificatesDa'wI' private keysDa'wI' Java applicationsDa'wI' utilizeDa'wI'.

PowerShellDa'wI' command promptDa'wI' jImejDa'wI' mentioned extensionsDa'wI' searchDa'wI'.

PKCS#12 certificate fileDa'wI' jImejDa'wI' passwordDa'wI' protectedDa'wI', hashDa'wI' extractionDa'wI' possibleDa'wI' `pfx2john.py`Da'wI' jImejDa'wI' [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html)Da'wI'. Subsequently, JohnTheRipperDa'wI' jImejDa'wI' passwordDa'wI' crackDa'wI' attemptDa'wI'.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

**THEFT5** is a method for stealing NTLM credentials through PKINIT. When PKINIT is used to support NTLM authentication for applications that don't use Kerberos authentication, the KDC returns the user's NTLM one-way function (OWF) within the privilege attribute certificate (PAC), specifically in the `PAC_CREDENTIAL_INFO` buffer. This allows the current host to extract the NTLM hash from the Ticket-Granting Ticket (TGT) obtained through PKINIT, enabling support for legacy authentication protocols. The process involves decrypting the `PAC_CREDENTIAL_DATA` structure, which is an NDR serialized representation of the NTLM plaintext.

The utility **Kekeo**, available at [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), can be used to request a TGT that contains this specific data, making it possible to retrieve the user's NTLM. The command used for this purpose is as follows:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
QongDaq, jImej Kekeo vItlhutlhlaHbe'chugh, pin vItlhutlhlaHbe'chugh, [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) Daq. **Rubeus** jImej, [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) Daq, 'ej vItlhutlhlaHbe'chugh.

vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh PKINIT vItlhutlhlaHbe'chugh NTLM hash vItlhutlhlaHbe'chugh TGT vItlhutlhlaHbe'chugh retrieval vItlhutlhlaHbe'chugh, 'ej vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qaStaHvIS AWS hacking</strong></a><strong>!</strong></summary>

HackTricks vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh:

* **company HackTricks** vItlhutlhlaHbe'chugh **advertised** vItlhutlhlaHbe'chugh **want** vItlhutlhlaHbe'chugh **PDF HackTricks** vItlhutlhlaHbe'chugh [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) vItlhutlhlaHbe'chugh!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) vItlhutlhlaHbe'chugh
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) vItlhutlhlaHbe'chugh [**NFTs**](https://opensea.io/collection/the-peass-family) vItlhutlhlaHbe'chugh
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) vItlhutlhlaHbe'chugh **Join** vItlhutlhlaHbe'chugh **telegram group**](https://t.me/peass) vItlhutlhlaHbe'chugh **follow** vItlhutlhlaHbe'chugh **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **hacking tricks** vItlhutlhlaHbe'chugh **Share** vItlhutlhlaHbe'chugh **submitting PRs** vItlhutlhlaHbe'chugh [**HackTricks**](https://github.com/carlospolop/hacktricks) [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos vItlhutlhlaHbe'chugh.

</details>
