import subprocess
import argparse
import os
import shutil
import zipfile
import lief
from androguard.core.bytecodes import apk

args: argparse.Namespace


def get_package_name():
    """Return package name of apk."""
    a = apk.APK(args.apk)
    package_name = a.get_package()
    return package_name


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", type=str, help="Path to the APK file", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    return args


def get_adb_devices():
    output = check_output(["adb", "devices"])
    output = output.decode("utf-8")
    lines = output.split("\n")
    devices = []
    for line in lines[1:]:
        if "\t" not in line:
            continue
        device = line.split("\t")[0]
        devices.append(device)
    return devices


def install_apk(device) -> bool:
    package_name = get_package_name()
    print(f"Package name: {package_name}")
    print(f"Installing APK on device {device}")
    call(["adb", "-s", device, "shell", "am", "force-stop", package_name])
    call(["adb", "-s", device, "uninstall", package_name])
    cmd = ["adb", "-s", device, "install", "-r", args.apk]
    if args.verbose:
        print(" ".join(cmd))
    result = subprocess.run(cmd, stdout=subprocess.PIPE).stdout
    if b"Success" in result:
        print("APK installed successfully")
        return True
    print("APK installation failed")
    return False


def get_device_abi(device):
    output = check_output(["adb", "-s", device, "shell", "getprop", "ro.product.cpu.abi"])
    output = output.decode("utf-8")
    return output.strip()


def ensure_frida_server(device):
    abi = get_device_abi(device)
    frida_server = None
    for file in os.listdir("frida-servers"):
        if file.endswith(abi):
            frida_server = "frida-servers/" + file
            break
    if frida_server is None:
        raise Exception(f"No frida server found for ABI {abi} under frida-servers directory")
    try:
        output = check_output(["adb", "-s", device, "shell", "ls", "/data/local/tmp/frida-server"])
        if b"frida-server" in output:
            print("Frida server already exists on device")
            return
    except subprocess.CalledProcessError:
        pass
    print(f"Pushing frida server to device {device}")
    call(["adb", "-s", device, "push", frida_server, "/data/local/tmp/frida-server"])
    call(["adb", "-s", device, "shell", "chmod", "755", "/data/local/tmp/frida-server"])


def ensure_agent(device):
    try:
        output = check_output(["adb", "-s", device, "shell", "ls", "/data/local/tmp/agent.dex"])
        if b"agent.dex" in output:
            print("Agent already exists on device")
            return
    except subprocess.CalledProcessError:
        pass
    print(f"Pushing agent to device {device}")
    call(["adb", "-s", device, "push", "agent-dex/classes.dex", "/data/local/tmp/agent.dex"])


def get_device():
    devices = get_adb_devices()
    if len(devices) == 0:
        raise Exception("No devices connected")
    elif len(devices) > 1:
        for i, device in enumerate(devices):
            print(f"{i}: {device}")
        device_index = int(input("Select device: "))
        device = devices[device_index]
    else:
        device = devices[0]
    return device


def place_agent_in_apk(agent_libs):
    # copy apk to apk[-4] + ".new.apk" to save original file
    new_apk = args.apk[:-4] + ".new.apk"
    shutil.copyfile(args.apk, new_apk)
    # get all .so files from apk
    found_abis = []
    with zipfile.ZipFile(args.apk, "r") as zip_ref:
        names = zip_ref.namelist()
        so_files = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
        # extract all .so files from apk
        for so_file in so_files:
            if not so_file.split("/")[1] in found_abis:
                found_abis.append(so_file.split("/")[1])
            zip_ref.extract(so_file)
            libnative = lief.parse(so_file)
            libnative.add_library("libagent.so")  # Injection!
            libnative.write(so_file)
            # to verify: readelf -d 'lib/x86/liblog.so' | grep NEEDED
            call(["aapt", "remove", new_apk, so_file])
            call(["aapt", "add", new_apk, so_file])
            os.remove(so_file)

    # executes aapt add app-debug.apk  libs\x86\libagent.so
    for found_abi in found_abis:
        call(["aapt", "add", new_apk, f"{agent_libs}/{found_abi}/libagent.so"])
    args.apk = new_apk


def zipalign():
    # align the zip file as required to be an apk,
    # done twice because sometimes it causes an error during installation
    # especially when aapt add/remove used
    print("Zipaligning APK")
    call(["zipalign", "-f", "4", args.apk, args.apk[:-4] + ".aligned1.apk"])
    call(["zipalign", "-f", "4", args.apk[:-4] + ".aligned1.apk", args.apk[:-4] + ".aligned.apk"])
    args.apk = args.apk[:-4] + ".aligned.apk"


def resign():
    # resign because modified apk has no more valid signature anymore
    print("Resigning APK")
    zipalign()
    call([
        "apksigner", "sign", "--ks", "debug.keystore", "--ks-key-alias", "androiddebugkey", "--ks-pass", "pass:android", "--key-pass", "pass:android",
        args.apk
    ],
         shell=True)


def call(cmd, shell=True):
    if args.verbose:
        if isinstance(cmd, list):
            cmd = " ".join(cmd)
        print(cmd)
    subprocess.call(cmd, shell=shell)


def check_output(cmd, shell=True):
    if args.verbose:
        if isinstance(cmd, list):
            cmd = " ".join(cmd)
        print(cmd)
    return subprocess.check_output(cmd, shell=shell)


def check_args():
    if not os.path.exists(args.apk):
        raise ValueError("APK path '%s' does not exist." % args.apk)


def main():
    global args
    args = parse_args()
    check_args()
    device = get_device()
    print(f"Device: {device}")
    ensure_frida_server(device)
    ensure_agent(device)
    place_agent_in_apk("lib")
    resign()
    if install_apk(device):
        print("Starting package")
        # check if frida running
        while True:
            try:
                output = check_output(["adb", "-s", device, "shell", "ps", "-A"])
            except subprocess.CalledProcessError:
                output = check_output(["adb", "-s", device, "shell", "ps"])
            if b"frida" not in output:
                input(f"""command 1-> adb -s {device} shell
command 2-> su
command 3-> /data/local/tmp/frida-server &
Run frida server with above commands and press enter to continue
""")
            else:
                break
        call(["frida", "-U", "-f", get_package_name(), "-l", "main.js"])


if __name__ == "__main__":
    main()
