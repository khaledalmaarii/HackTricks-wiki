<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

# Guia de Decompilação Wasm e Compilação Wat

No mundo do **WebAssembly**, ferramentas de **decompilação** e **compilação** são essenciais para os desenvolvedores. Este guia apresenta alguns recursos online e software para lidar com arquivos **Wasm (binário WebAssembly)** e **Wat (texto WebAssembly)**.

## Ferramentas Online

- Para **decompilar** Wasm para Wat, a ferramenta disponível em [demo wasm2wat do Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) é útil.
- Para **compilar** Wat de volta para Wasm, [demo wat2wasm do Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) atende ao propósito.
- Outra opção de decompilação pode ser encontrada em [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Soluções de Software

- Para uma solução mais robusta, [JEB da PNF Software](https://www.pnfsoftware.com/jeb/demo) oferece recursos extensivos.
- O projeto de código aberto [wasmdec](https://github.com/wwwg/wasmdec) também está disponível para tarefas de decompilação.

# Recursos de Decompilação .Net

Decompilar assemblies .Net pode ser feito com ferramentas como:

- [ILSpy](https://github.com/icsharpcode/ILSpy), que também oferece um [plugin para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), permitindo o uso multiplataforma.
- Para tarefas envolvendo **decompilação**, **modificação** e **recompilação**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) é altamente recomendado. Ao clicar com o botão direito em um método e escolher **Modificar Método**, é possível fazer alterações no código.
- [dotPeek da JetBrains](https://www.jetbrains.com/es-es/decompiler/) é outra alternativa para decompilar assemblies .Net.

## Aprimorando a Depuração e o Log com DNSpy

### Log do DNSpy
Para registrar informações em um arquivo usando o DNSpy, incorpore o trecho de código .Net a seguir:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Senha: " + senha + "\n");
%%%

### Depuração do DNSpy
Para uma depuração eficaz com o DNSpy, é recomendada uma sequência de etapas para ajustar os **atributos da Assembleia** para depuração, garantindo que otimizações que possam dificultar a depuração sejam desativadas. Esse processo inclui alterar as configurações do `DebuggableAttribute`, recompilar a assembleia e salvar as alterações.

Além disso, para depurar uma aplicação .Net executada pelo **IIS**, executar `iisreset /noforce` reinicia o IIS. Para anexar o DNSpy ao processo do IIS para depuração, o guia instrui a selecionar o processo **w3wp.exe** dentro do DNSpy e iniciar a sessão de depuração.

Para uma visão abrangente dos módulos carregados durante a depuração, é aconselhável acessar a janela **Módulos** no DNSpy, seguida pela abertura de todos os módulos e classificação das assembleias para facilitar a navegação e a depuração.

Este guia encapsula a essência da decompilação de WebAssembly e .Net, oferecendo um caminho para os desenvolvedores navegarem nessas tarefas com facilidade.

## **Descompilador Java**
Para descompilar bytecode Java, essas ferramentas podem ser muito úteis:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Depuração de DLLs**
### Usando IDA
- **Rundll32** é carregado a partir de caminhos específicos para versões de 64 bits e 32 bits.
- **Windbg** é selecionado como o depurador com a opção de suspender no carregamento/descarregamento da biblioteca ativada.
- Os parâmetros de execução incluem o caminho da DLL e o nome da função. Essa configuração interrompe a execução a cada carregamento da DLL.

### Usando x64dbg/x32dbg
- Semelhante ao IDA, **rundll32** é carregado com modificações na linha de comando para especificar a DLL e a função.
- As configurações são ajustadas para interromper na entrada da DLL, permitindo a configuração de pontos de interrupção no ponto de entrada desejado da DLL.

### Imagens
- Pontos de parada de execução e configurações são ilustrados por meio de capturas de tela.

## **ARM & MIPS**
- Para emulação, [arm_now](https://github.com/nongiach/arm_now) é um recurso útil.

## **Shellcodes**
### Técnicas de Depuração
- **Blobrunner** e **jmp2it** são ferramentas para alocar shellcodes na memória e depurá-los com Ida ou x64dbg.
- Blobrunner [lançamentos](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [versão compilada](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** oferece emulação e inspeção de shellcode baseada em GUI, destacando diferenças no tratamento de shellcode como arquivo versus shellcode direto.

### Desobfuscação e Análise
- **scdbg** fornece insights sobre funções de shellcode e capacidades de desobfuscação.
%%%bash
scdbg.exe -f shellcode # Informações básicas
scdbg.exe -f shellcode -r # Relatório de análise
scdbg.exe -f shellcode -i -r # Ganchos interativos
scdbg.exe -f shellcode -d # Despejar shellcode decodificado
scdbg.exe -f shellcode /findsc # Encontrar offset de início
scdbg.exe -f shellcode /foff 0x0000004D # Executar a partir do offset
%%%

- **CyberChef** para desmontar shellcode: [Receita CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Um ofuscador que substitui todas as instruções por `mov`.
- Recursos úteis incluem uma [explicação no YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) e [slides em PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** pode reverter a obfuscação do movfuscator, exigindo dependências como `libcapstone-dev` e `libz3-dev`, e a instalação do [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Para binários Delphi, é recomendado o [IDR](https://github.com/crypto2011/IDR).

# Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Desobfuscação binária\)

</details>
