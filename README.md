# Talos DBI DR clients — DBI with DynamoRIO

A collection of **Dynamic Binary Instrumentation (DBI)** clients and utilities built on top of **[DynamoRIO](https://dynamorio.org)**. The clients are inspired by the REcon conference talk **“Attacking Modern Software Protection with Dynamic Binary Instrumentation”** by **Holger Unterbrink (Cisco Talos)**.

This project helps reverse engineers, researchers, and security enthusiasts get hands-on with DynamoRIO through practical, reusable examples.

All clients and samples are build for Microsoft Windows 11. 

If you are new to DynamoRio, please read the HU-DBI-Recon2025.pdf paper to get started (see below).
  

## WARNING 
Keep in mind DBI is executing the target application (e.g. malware sample) on the machine where you are running the client on. If you are running the clients against malware, never do that on a production machine, always use a VM or dedicated malware PC which you can restore
easily afterwards !

---

## Features

- Example DBI clients tailored for reverse-engineering tasks
- Practical use cases based on software-protection attacks
- A solid starting point to extend and build your own DynamoRIO tools
- Learn how to instrument binaries and experiment with runtime analysis
- Assemble your own tooling for research and reversing workflows

We love contributions — especially **your DBI clients**. See [Contributing](https://github.com/Cisco-Talos/DBI/blob/main/CONTRIBUTING.md).

---

## Repository layout

### “How to get started” clients

| Client | Description |
| --- | --- |
| `simple_client` | The simplest “hello world” DynamoRIO client. |
| `simple_client2` | Still simple; prints all modules loaded at runtime. |
| `simple_client3` | Traces all instructions within a specified address range. |
| `tracer-calltracer` | Dumps all calls and resolves API function names where possible. |
| `tracer-strdump` | Dumps potential strings the **source operand** points to within a specified range. |
| `tracer-memdump` | Dumps memory data the **source operand** points to within a specified range. |

### Docs
| `HU-DBI-Recon2025.pdf` | Recon talk |

### Malware-simulation samples (for testing clients)

| Sample | Description |
| --- | --- |
| `anti_x` | Simulates typical malware obfuscation/anti-analysis behaviors without doing anything malicious. |
| `RelaunchMe` | Restarts itself from the temp directory. |
| `stringdecoder` | Simple decoder for a lightly obfuscated “Hello World!” string. |

---

## Getting started

### Prerequisites
- Install **[DynamoRIO](http://dynamorio.org/)** (Clients were tested with DR 11.3.0)
- Installing DynamoRio is as easy as downloading it and unzipping it to a directory 
- Some test scripts assume to find "drrun.exe" at "C:\tools\DynamoRIO-Windows-11.3.0\bin32\drrun.exe"
- Either make sure you are using the same directory or edit the scripts
- Microsoft Visual Studio 2019 (recommended) or later
- CMAKE (installed with Visual Studio)

### Build 
- We are running and compiling the examples in MSYS2, but it should work in a normal MS Dev Prompt, too
- You can find build scripts named "MSYS_build32.sh" and "MSYS_build64.sh" inside the client directories
- They are building the client DLLs by using CMake.
- The Malware simulation examples from above are build with VisualStudio 2019 or later.

### Run client DLLs with DynamoRio
- Start a MSYS2 shell on Windows (all scripts are tested with Windows 11 24H2)
- Most client directories have a "run_tracer32.sh" and "run_tracer64.sh" example bash script or similar as an example how to execute the client DLL with a sample target application




