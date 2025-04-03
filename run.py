import json
import lzma
import zipfile
from zipfile import ZipFile
import shutil
import os
import requests
import sys
import argparse
from shutil import which
import subprocess

# Config
TEMP_FOLDER = os.path.join(os.getcwd(), "temp")
DEFAULT_OUTPUT_NAME = "instagram_patched.apk"
SUPPORTED_ARCHS = ["x86", "x86_64", "armeabi-v7a", "arm64-v8a"]
FRIDA_GADGET_CONFIG = {
    "interaction": {
        "type": "script",
        "path": "./libsslbypass.js.so"
    },
    "runtime": {
        "blacklist": "frida"
    }
}

class ApkToolError(Exception):
    pass

class FridaDownloadError(Exception):
    pass

def create_temp_folder():
    if os.path.exists(TEMP_FOLDER):
        shutil.rmtree(TEMP_FOLDER)
    os.makedirs(TEMP_FOLDER)

def is_tool_installed(name):
    return which(name) is not None

def check_tools():
    required_tools = ["keytool", "apksigner", "zipalign", "apktool"]
    missing = [tool for tool in required_tools if not is_tool_installed(tool)]
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        return False
    return True

def unpack_apk(apk_path):
    out_dir = os.path.join(TEMP_FOLDER, "app")
    cmd = f'apktool d -r -f "{apk_path}" -o "{out_dir}"'
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        raise ApkToolError(f"Failed to unpack APK: {e}")

def pack_apk():
    app_dir = os.path.join(TEMP_FOLDER, "app")
    output_apk = os.path.join(TEMP_FOLDER, "patched.apk")
    cmd = f'apktool b "{app_dir}" -o "{output_apk}"'
    subprocess.run(cmd, shell=True, check=True)
    return output_apk

def create_keystore(keystore_path, key_alias, store_pass):
    cmd = (
        f'keytool -genkeypair -v '
        f'-keystore "{keystore_path}" '
        f'-alias {key_alias} '
        f'-keyalg RSA -keysize 2048 '
        f'-validity 10000 '
        f'-storepass {store_pass} '
        f'-keypass {store_pass} '
        f'-dname "CN=Android Debug,O=Android,C=US"'
    )
    try:
        subprocess.run(cmd, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Keytool error: {e}")
        return False

def sign_apk(apk_path, keystore_path, key_alias, store_pass):
    cmd = (
        f'apksigner sign --ks "{keystore_path}" '
        f'--ks-key-alias {key_alias} '
        f'--ks-pass pass:{store_pass} '
        f'"{apk_path}"'
    )
    subprocess.run(cmd, shell=True, check=True)

def zipalign_apk(apk_path):
    aligned_path = apk_path.replace(".apk", "_aligned.apk")
    cmd = f'zipalign -p -f 4 "{apk_path}" "{aligned_path}"'
    subprocess.run(cmd, shell=True, check=True)
    os.remove(apk_path)
    os.rename(aligned_path, apk_path)

def download_frida_gadget(arch, version=None):
    arch_map = {
        "armeabi-v7a": "arm",
        "arm64-v8a": "arm64",
        "x86": "x86",
        "x86_64": "x86_64"
    }

    if version is None:
        version = "latest"
        url = "https://api.github.com/repos/frida/frida/releases/latest"
    else:
        url = f"https://api.github.com/repos/frida/frida/releases/tags/{version}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        release = response.json()
        assets = release.get("assets", [])

        for asset in assets:
            asset_name = asset["name"]
            if f"frida-gadget-{arch_map[arch]}-android" in asset_name and asset_name.endswith(".so.xz"):
                gadget_url = asset["browser_download_url"]
                gadget_path = os.path.join(TEMP_FOLDER, f"frida-gadget-{arch}.so.xz")
                
                print(f"[*] Downloading Frida gadget for {arch}...")
                with requests.get(gadget_url, stream=True) as r:
                    r.raise_for_status()
                    with open(gadget_path, "wb") as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)
                
                lib_dir = os.path.join(TEMP_FOLDER, "app", "lib", arch)
                os.makedirs(lib_dir, exist_ok=True)
                
                with lzma.open(gadget_path) as f:
                    with open(os.path.join(lib_dir, "libfrida-gadget.so"), "wb") as out:
                        out.write(f.read())
                
                os.remove(gadget_path)
                return True
    except Exception as e:
        raise FridaDownloadError(f"Failed to download Frida gadget: {e}")
    
    return False

def create_frida_config():
    config_path = os.path.join(TEMP_FOLDER, "frida.config.so")
    with open(config_path, "w") as f:
        json.dump(FRIDA_GADGET_CONFIG, f)
    return config_path

def copy_frida_script():
    script_content = """Java.perform(function() {
    // Bypass OkHttp
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {};
    
    // Bypass TrustManager
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    X509TrustManager.checkServerTrusted.implementation = function() { return this; };
    
    // Bypass Android Network Security Config
    var NetworkSecurityPolicy = Java.use("android.security.net.config.NetworkSecurityPolicy");
    NetworkSecurityPolicy.isCertificateTransparencyVerificationRequired.implementation = function() { return false; };
});

// Native SSL Bypass
Interceptor.attach(Module.findExportByName("libssl.so", "SSL_CTX_set_verify"), {
    onEnter: function(args) { args[2] = ptr(0); }
});"""
    
    script_path = os.path.join(TEMP_FOLDER, "libsslbypass.js.so")
    with open(script_path, "w") as f:
        f.write(script_content)
    return script_path

def find_target_class():
    smali_dir = os.path.join(TEMP_FOLDER, "app", "smali")
    target_classes = []

    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith(".smali"):
                with open(os.path.join(root, file), "r", encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if ("Ljavax/net/ssl/" in content or 
                        "Lokhttp3/" in content or 
                        "Landroid/webkit/" in content):
                        target_classes.append(os.path.join(root, file))

    return target_classes[0] if target_classes else None

def inject_load_library(target_class):
    with open(target_class, "r", encoding='utf-8') as f:
        smali = f.readlines()

    # Find injection point
    injection_point = None
    for i, line in enumerate(smali):
        if ".method static constructor <clinit>()V" in line:
            injection_point = i
            break
    
    if injection_point is None:
        # Add new static constructor
        new_constructor = [
            ".method static constructor <clinit>()V\n",
            "    .locals 1\n",
            "    .prologue\n",
            '    const-string v0, "frida-gadget"\n',
            "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n",
            "    return-void\n",
            ".end method\n"
        ]
        with open(target_class, "w", encoding='utf-8') as f:
            f.writelines(new_constructor + smali)
    else:
        # Inject into existing constructor
        smali.insert(injection_point + 2, '    const-string v0, "frida-gadget"\n')
        smali.insert(injection_point + 3, "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n")
        with open(target_class, "w", encoding='utf-8') as f:
            f.writelines(smali)

def main():
    parser = argparse.ArgumentParser(description="Bypass SSL Pinning in Instagram APK")
    parser.add_argument("-i", "--input", required=True, help="Input APK file")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_NAME, help="Output APK file")
    parser.add_argument("--keystore", help="Custom keystore path")
    parser.add_argument("--keyalias", default="androiddebugkey", help="Keystore alias")
    parser.add_argument("--storepass", default="android", help="Keystore password")
    parser.add_argument("--frida-version", help="Frida gadget version (e.g. 16.1.11)")
    args = parser.parse_args()

    if not check_tools():
        sys.exit(1)

    try:
        create_temp_folder()
        shutil.copy(args.input, os.path.join(TEMP_FOLDER, "original.apk"))

        print("[*] Unpacking APK...")
        unpack_apk(os.path.join(TEMP_FOLDER, "original.apk"))

        print("[*] Finding target class...")
        target_class = find_target_class()
        if not target_class:
            raise Exception("No suitable target class found for injection")

        print("[*] Injecting Frida gadget...")
        inject_load_library(target_class)

        print("[*] Setting up Frida...")
        config_path = create_frida_config()
        script_path = copy_frida_script()

        print("[*] Processing architectures...")
        for arch in SUPPORTED_ARCHS:
            lib_dir = os.path.join(TEMP_FOLDER, "app", "lib", arch)
            if not os.path.exists(lib_dir):
                continue

            print(f"[*] Processing {arch}...")
            download_frida_gadget(arch, args.frida_version)
            shutil.copy(config_path, os.path.join(lib_dir, "libfrida.config.so"))
            shutil.copy(script_path, os.path.join(lib_dir, "libsslbypass.js.so"))

        print("[*] Rebuilding APK...")
        output_apk = pack_apk()

        print("[*] Signing APK...")
        if args.keystore:
            keystore_path = args.keystore
        else:
            keystore_path = os.path.join(TEMP_FOLDER, "debug.keystore")
            if not create_keystore(keystore_path, args.keyalias, args.storepass):
                raise Exception("Failed to create keystore")

        sign_apk(output_apk, keystore_path, args.keyalias, args.storepass)
        zipalign_apk(output_apk)

        shutil.move(output_apk, args.output)
        print(f"\n[+] Success! Patched APK saved to: {args.output}")

    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(TEMP_FOLDER):
            shutil.rmtree(TEMP_FOLDER)

if __name__ == "__main__":
    main()
