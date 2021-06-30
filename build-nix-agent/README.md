## Build Installer
```
chmod +x build.sh
./build.sh
```

## Install
```
sudo apt install ./ww-capture-agent.deb
```

## Uninstall
```
sudo dpkg -r ww-capture-agent
```

## Send installer to file server
```
scp ww-capture-agent.deb pi@192.168.1.110:/etc/caddy/files/ww-capture-agent.deb
```
