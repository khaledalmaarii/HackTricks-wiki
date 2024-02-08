# BloodHound e Outras Ferramentas de Enumeração AD

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) é da Suite Sysinternal:

> Um visualizador e editor avançado do Active Directory (AD). Você pode usar o AD Explorer para navegar facilmente em um banco de dados AD, definir locais favoritos, visualizar propriedades de objetos e atributos sem abrir caixas de diálogo, editar permissões, visualizar o esquema de um objeto e executar pesquisas sofisticadas que você pode salvar e reexecutar.

### Capturas de Tela

O AD Explorer pode criar capturas de tela de um AD para que você possa ver offline.\
Pode ser usado para descobrir vulnerabilidades offline ou para comparar diferentes estados do banco de dados AD ao longo do tempo.

Será necessário o nome de usuário, senha e direção para se conectar (qualquer usuário AD é necessário).

Para fazer uma captura de tela do AD, vá para `Arquivo` --> `Criar Captura de Tela` e insira um nome para a captura.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) é uma ferramenta que extrai e combina vários artefatos de um ambiente AD. As informações podem ser apresentadas em um **relatório Microsoft Excel formatado** que inclui visualizações de resumo com métricas para facilitar a análise e fornecer uma imagem holística do estado atual do ambiente AD de destino.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

De [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound é uma aplicação web de página única em Javascript, construída em cima do [Linkurious](http://linkurio.us/), compilada com [Electron](http://electron.atom.io/), com um banco de dados [Neo4j](https://neo4j.com/) alimentado por um coletor de dados em C#.

BloodHound utiliza a teoria dos grafos para revelar os relacionamentos ocultos e muitas vezes não intencionais dentro de um ambiente de Active Directory ou Azure. Atacantes podem usar o BloodHound para identificar facilmente caminhos de ataque altamente complexos que de outra forma seriam impossíveis de identificar rapidamente. Defensores podem usar o BloodHound para identificar e eliminar esses mesmos caminhos de ataque. Tanto equipes azuis quanto vermelhas podem usar o BloodHound para obter facilmente uma compreensão mais profunda dos relacionamentos de privilégio em um ambiente de Active Directory ou Azure.

Portanto, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) é uma ferramenta incrível que pode enumerar um domínio automaticamente, salvar todas as informações, encontrar possíveis caminhos de escalonamento de privilégios e mostrar todas as informações usando gráficos.

Booldhound é composto por 2 partes principais: **ingestores** e a **aplicação de visualização**.

Os **ingestores** são usados para **enumerar o domínio e extrair todas as informações** em um formato que a aplicação de visualização entenderá.

A **aplicação de visualização usa o neo4j** para mostrar como todas as informações estão relacionadas e para mostrar diferentes maneiras de escalar privilégios no domínio.

### Instalação
Após a criação do BloodHound CE, todo o projeto foi atualizado para facilitar o uso com Docker. A maneira mais fácil de começar é usar sua configuração pré-configurada do Docker Compose.

1. Instale o Docker Compose. Isso deve estar incluído na instalação do [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Execute:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Localize a senha gerada aleatoriamente na saída do terminal do Docker Compose.
4. Em um navegador, acesse http://localhost:8080/ui/login. Faça login com um nome de usuário de admin e a senha gerada aleatoriamente nos logs.

Após isso, você precisará alterar a senha gerada aleatoriamente e terá a nova interface pronta, da qual poderá baixar diretamente os ingestores.

### SharpHound

Eles têm várias opções, mas se você deseja executar o SharpHound de um PC conectado ao domínio, usando seu usuário atual e extrair todas as informações, você pode fazer:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Você pode ler mais sobre **CollectionMethod** e sessão de loop [aqui](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Se desejar executar o SharpHound usando credenciais diferentes, você pode criar uma sessão CMD netonly e executar o SharpHound a partir dela:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Saiba mais sobre o Bloodhound em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) é uma ferramenta para encontrar **vulnerabilidades** no Active Directory associadas à **Política de Grupo**. \
Você precisa **executar o group3r** a partir de um host dentro do domínio usando **qualquer usuário do domínio**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **avalia a postura de segurança de um ambiente AD** e fornece um **relatório** detalhado com gráficos.

Para executá-lo, você pode rodar o executável `PingCastle.exe` e ele iniciará uma **sessão interativa** apresentando um menu de opções. A opção padrão a ser usada é **`healthcheck`** que estabelecerá uma **visão geral** da **domínio**, e encontrará **configurações incorretas** e **vulnerabilidades**.&#x20;
