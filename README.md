# DynamicCodeMonitorAndReplace-pipeline

## Dynamic Code Loading Monitor
- This tool is developed to monitor dynamic code loading in Android apps and replace the loaded code with my injected one.

### Java/Dex
- Replaces loaded .dex with agent's dex
- Forwards call to agent's function with function name as an argument
- Makes a toast with function name
  
### Native
- It modifies apk file to inject agent(libagent.so) library under lib/{abi}
- libagent.so:
  - sets a signal handler for SIGSEGV(11) signal to "handle_signal" function
  - if signal code is SEGV_ACCERR then calls the report function with the address of the crash
  - "report" function is replaced by our frida function in "main.js"
- main.js
  - Hooks mmap, mmap64 and mprotect to keep track of executable memory blocks
  - Removes executable flag from loaded memory blocks
  - Replaces "report" function with our own function that checks if the crash address is in the dynamically loaded memory blacklist

## Requirements

- Required binaries from [Android SDK](https://developer.android.com/studio/releases/platform-tools) in platform-tools/
 - adb
 - apksigner
 - aapt
 - python
 - pip
 - d8

- Python requirements
```
pip install -r requirements.txt
```
- JDK-11 (check with javac --version)
- Agent.class (if exists remove it in the device, /data/local/tmp/agent.dex)
```
javac agent-dex/Agent.java
```

- classes.dex of Agent.class (this will pushed to device automatically)
```
cd agent-dex
d8 --release Agent.class
```
- Running emulator 
- [Frida servers](https://github.com/frida/frida/releases) in frida-servers/ (these will be pushed to device regarding to their ABI automatically)
- Execute run.py [ WARNING: This will run the app on the connected device]
```
python run.py -a app.apk --verbose
```
