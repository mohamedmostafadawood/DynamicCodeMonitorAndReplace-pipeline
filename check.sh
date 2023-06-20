#!/bin/bash

if [ -z "$(which adb)" ]; then
    echo "[-] adb not found"
else
    echo "[+] adb found"
fi

if [ -z "$(which apksigner)" ]; then
    echo "[-] apksigner not found"
else
    echo "[+] apksigner found"
fi

if [ -z "$(which zipalign)" ]; then
    echo "[-] zipalign not found"
else
    echo "[+] zipalign found"
fi

if [ -z "$(which aapt)" ]; then
    echo "[-] aapt not found"
else
    echo "[+] aapt found"
fi

if [ -z "$(which python)" ]; then
    echo "[-] python not found"
else
    echo "[+] python found"
fi

if [ -z "$(which pip)" ]; then
    echo "[-] pip not found"
else
    echo "[+] pip found"
fi


if [ -z "$(which d8)" ]; then
    echo "[-] d8 not found"
else
    echo "[+] d8 found"
fi


if [ -z "$(javac --version | grep 'javac 11.')" ]; then
    echo "[-] java version is not 11"
else
    echo "[+] java version is 11"
fi

if [ "$(ls frida-servers/ | wc -l)" -ne 4 ]; then
    echo "[-] frida-servers/ is not complete"
else
    echo "[+] frida-servers/ is complete"
fi

if [ "$(ls lib/ | wc -l)" -ne 4 ]; then
    echo "[-] lib/ is not complete"
else
    echo "[+] lib/ is complete"
fi
