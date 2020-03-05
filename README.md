# Snikket Web Portal

## Start the dev server

```console
$ direnv allow
$ mkdir .local
$ cp web_config.example.py .local/web_config.py
$ $EDITOR .local/web_config.py  # to adapt the configuration to your needs
$ pip install -r requirements.txt
$ pip install -r build-requirements.txt
$ make
$ quart run
```
