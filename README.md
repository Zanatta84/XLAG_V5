# XLAG_V5
Ferramenta GUI avançada para manipulação de pacotes de rede em tempo real usando WinDivert e pydivert. Desenvolvido para consoles PS5 com foco em The Division 2, permite aplicar lag, perda, duplicação e "data burst" em pacotes com classificação dinâmica e controle por teclado.
Principais recursos:

Interface gráfica (Tkinter)

Manipulação de pacotes UDP (latência, jitter, perda, duplicação, corrupção, burst)

Integração com WinDivert

Logging em tempo real

Controle por teclado (F1, F2, F3, CTRL)

Salvamento e carregamento de presets

Requer privilégios de administrador

📦 Arquivos do Projeto
No seu repositório, organize os arquivos assim:

bash
Copiar
Editar
xlag-turbo-gui/
│
├── xlag_turbo_gui_v1_9_8_fixed_burst.py    # Script principal
├── README.md                               # Descrição do projeto
├── requirements.txt                        # Bibliotecas necessárias
└── LICENSE                                 # Licença de uso
📁 1. Criar o Repositório no GitHub
Acesse github.com

Clique em New repository

Preencha os dados:

Repository name: xlag-turbo-gui

Description: Ferramenta de manipulação de pacotes com GUI para PS5 (The Division 2)

Public (ou Private, se preferir)

Clique em Create repository

💻 2. Subir o Código
No seu terminal:

bash
Copiar
Editar
# Navegue até a pasta onde está seu script
cd /caminho/do/seu/projeto

# Inicialize o repositório local
git init
git remote add origin https://github.com/seu-usuario/xlag-turbo-gui.git

# Crie o arquivo requirements.txt
echo pydivert > requirements.txt
echo pynput >> requirements.txt

# (Opcional) Adicione um README
echo "# xLag Turbo GUI" > README.md

# Adicione e envie os arquivos
git add .
git commit -m "Versão inicial - xLag Turbo GUI v1.9.8"
git push -u origin master
📄 Exemplo de README.md
Você pode usar este conteúdo como base:

markdown
Copiar
Editar
# xLag Turbo GUI v1.9.8

Ferramenta GUI para manipulação de pacotes de rede em tempo real com foco em The Division 2 (PS5).

## Recursos
- Latência, Jitter, Perda de Pacotes, Duplicação, Corrupção
- Classificação de pacotes (MOVIMENTO, DANO, OUTROS)
- Data Burst configurável
- Interface gráfica com Tkinter
- Salvar/Carregar presets
- Controle por teclado (F1, F2, F3, CTRL)
- Logging em tempo real (JSON e CSV)

## Requisitos
- Windows com permissões de administrador
- Python 3.8+
- [WinDivert](https://reqrypt.org/windivert.html)
- `pydivert`, `pynput`

```bash
pip install -r requirements.txt
Aviso
Este projeto é para fins educacionais e experimentais. O uso indevido pode violar termos de serviço de jogos online.

Licença
MIT

yaml
Copiar
Editar

---

### ✅ **3. Rodando o Script**
Após instalar o Python e as dependências, rode:

```bash
python xlag_turbo_gui_v1_9_8_fixed_burst.py
Importante: Execute o script como administrador, senão o WinDivert não funcionará corretamente.
