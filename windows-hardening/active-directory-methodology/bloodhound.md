# BloodHound & Outras Ferramentas de Enumeração AD

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) é da Sysinternal Suite:

> Um visualizador e editor avançado de Active Directory (AD). Você pode usar o AD Explorer para navegar facilmente em um banco de dados AD, definir locais favoritos, visualizar propriedades de objetos e atributos sem abrir caixas de diálogo, editar permissões, visualizar o esquema de um objeto e executar pesquisas sofisticadas que você pode salvar e reexecutar.

### Capturas de Tela

O AD Explorer pode criar capturas de tela de um AD para que você possa verificá-lo offline.\
Ele pode ser usado para descobrir vulnerabilidades offline ou para comparar diferentes estados do banco de dados AD ao longo do tempo.

Você precisará do nome de usuário, senha e direção para se conectar (qualquer usuário AD é necessário).

Para tirar uma captura de tela do AD, vá para `File` --> `Create Snapshot` e insira um nome para a captura.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) é uma ferramenta que extrai e combina vários artefatos de um ambiente AD. As informações podem ser apresentadas em um **relatório** Microsoft Excel **especialmente formatado** que inclui visualizações resumidas com métricas para facilitar a análise e fornecer uma visão holística do estado atual do ambiente AD alvo.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound é uma aplicação web Javascript de página única, construída sobre [Linkurious](http://linkurio.us/), compilada com [Electron](http://electron.atom.io/), com um banco de dados [Neo4j](https://neo4j.com/) alimentado por um coletor de dados em C#.

BloodHound usa teoria dos grafos para revelar as relações ocultas e muitas vezes não intencionais dentro de um ambiente Active Directory ou Azure. Atacantes podem usar BloodHound para identificar facilmente caminhos de ataque altamente complexos que, de outra forma, seriam impossíveis de identificar rapidamente. Defensores podem usar BloodHound para identificar e eliminar esses mesmos caminhos de ataque. Tanto equipes azuis quanto vermelhas podem usar BloodHound para obter facilmente uma compreensão mais profunda das relações de privilégio em um ambiente Active Directory ou Azure.

Assim, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) é uma ferramenta incrível que pode enumerar um domínio automaticamente, salvar todas as informações, encontrar possíveis caminhos de escalonamento de privilégios e mostrar todas as informações usando gráficos.

BloodHound é composto por 2 partes principais: **ingestors** e a **aplicação de visualização**.

Os **ingestors** são usados para **enumerar o domínio e extrair todas as informações** em um formato que a aplicação de visualização entenderá.

A **aplicação de visualização usa neo4j** para mostrar como todas as informações estão relacionadas e para mostrar diferentes maneiras de escalar privilégios no domínio.

### Instalação
Após a criação do BloodHound CE, todo o projeto foi atualizado para facilitar o uso com Docker. A maneira mais fácil de começar é usar sua configuração pré-configurada do Docker Compose.

1. Instale o Docker Compose. Isso deve estar incluído na instalação do [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Execute:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Localize a senha gerada aleatoriamente na saída do terminal do Docker Compose.  
4. Em um navegador, navegue até http://localhost:8080/ui/login. Faça login com o nome de usuário admin e a senha gerada aleatoriamente dos logs.

Depois disso, você precisará alterar a senha gerada aleatoriamente e terá a nova interface pronta, a partir da qual você pode baixar diretamente os ingestors.

### SharpHound

Eles têm várias opções, mas se você quiser executar o SharpHound de um PC conectado ao domínio, usando seu usuário atual e extrair todas as informações, você pode fazer:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Você pode ler mais sobre **CollectionMethod** e a sessão de loop [aqui](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Se você deseja executar o SharpHound usando credenciais diferentes, pode criar uma sessão CMD netonly e executar o SharpHound a partir daí:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Saiba mais sobre Bloodhound em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) é uma ferramenta para encontrar **vulnerabilidades** no Active Directory associadas à **Política de Grupo**. \
Você precisa **executar group3r** a partir de um host dentro do domínio usando **qualquer usuário do domínio**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **avalia a postura de segurança de um ambiente AD** e fornece um bom **relatório** com gráficos.

Para executá-lo, pode-se executar o binário `PingCastle.exe` e ele iniciará uma **sessão interativa** apresentando um menu de opções. A opção padrão a ser utilizada é **`healthcheck`**, que estabelecerá uma **visão geral** do **domínio** e encontrará **configurações incorretas** e **vulnerabilidades**.&#x20;

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
