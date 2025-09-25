import frida
import sys

# ⛳️ Zielprogramm (CLI-Tool oder .exe mit Argumenten)
COMMAND_LINE = "RelaunchMe.exe"

# Frida JavaScript (wird in Zielprozess injiziert)
FRIDA_SCRIPT = """
var functions = [
    ["kernel32.dll", "CreateFileW"],
    ["kernel32.dll", "ReadFile"],
    ["kernel32.dll", "WriteFile"],
    ["kernel32.dll", "CloseHandle"]
];

function getStr(ptr) {
    try {
        if (ptr.isNull()) return "NULL";
        return ptr.readUtf16String();
    } catch (e) {
        return "<invalid>";
    }
}

function hook(dll, name) {
    try {
        var addr = Module.getExportByName(dll, name);
        if (!addr) {
            send({ type: "warn", message: name + " not found in " + dll });
            return;
        }

        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.name = name;

                if (name === "CreateFileW") {
                    send({
                        api: name,
                        file: getStr(args[0]),
                        access: args[1].toInt32()
                    });
                } else if (name === "ReadFile" || name === "WriteFile") {
                    send({
                        api: name,
                        handle: args[0].toString(),
                        size: args[2].toInt32()
                    });
                } else if (name === "CloseHandle") {
                    send({
                        api: name,
                        handle: args[0].toString()
                    });
                }
            },
            onLeave: function (retval) {
                send({
                    api: this.name,
                    return: retval.toInt32()
                });
            }
        });

        send({ type: "info", message: "Hooked " + name });

    } catch (e) {
        send({ type: "error", message: "Hook error in " + name + ": " + e });
    }
}

for (var i = 0; i < functions.length; i++) {
    var dll = functions[i][0];
    var name = functions[i][1];
    if (Module.findBaseAddress(dll)) {
        hook(dll, name);
    } else {
        send({ type: "warn", message: "DLL not loaded: " + dll });
    }
}
"""



def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        print(f"[{payload.get('api')}] → {payload}")
    elif message["type"] == "error":
        print("[!] Script error:", message["stack"])

def main():
    print(f"[+] Starte: {COMMAND_LINE}")
    try:
        pid = frida.spawn(COMMAND_LINE)
    except frida.ProcessNotFoundError:
        print(f"[!] Prozess konnte nicht gestartet werden: {COMMAND_LINE}")
        sys.exit(1)

    session = frida.attach(pid)
    script = session.create_script(FRIDA_SCRIPT)
    script.on("message", on_message)
    script.load()

    # Prozess starten (weiterlaufen lassen)
    frida.resume(pid)

    print("[*] Tracing läuft… STRG+C zum Beenden.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[+] Beendet.")

if __name__ == "__main__":
    main()
