# Talos DBI DR clients — DBI with DynamoRIO

A collection of **Dynamic Binary Instrumentation (DBI)** clients and utilities built on top of **[DynamoRIO](https://dynamorio.org)**. The clients are inspired by the REcon conference talk **“Attacking Modern Software Protection with Dynamic Binary Instrumentation”** by **Holger Unterbrink (Cisco Talos)**.

This project helps reverse engineers, researchers, and security enthusiasts get hands-on with DynamoRIO through practical, reusable examples. The clients are mainly build with the idea to keep them as simple as possible, to make it easier to understand the concept, 
not to make them bullet proof. For example, they are missing some exception or input checks, which you might want to add if your client runs in a productive environment. We also tried to keep it as flexible as possible, to make it easy to adapt the project to your personal
development environment. 

All clients and samples are build for Microsoft Windows 11. 

If you are new to DynamoRio, please read the corrosponding **[Talos blog post](https://blog.talosintelligence.com/dynamic-binary-instrumentation-dbi-with-dynamorio/)** to get started (see below).
  

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

| DR Client | Description |
| --- | --- |
| `simple_client` | The simplest “hello world” DynamoRIO client. |
| `simple_client2` | Still simple; prints all modules loaded at runtime. |
| `simple_client3` | Traces all instructions within a specified address range. |
| `tracer-calltracer` | Dumps all calls and resolves API function names where possible. |
| `tracer-strdump` | Dumps potential strings the **source operand** points to within a specified range. |
| `tracer-memdump` | Dumps memory data the **source operand** points to within a specified range. |

### Docs
| Doc file | Description |
| --- | --- |
| `HU-DBI-Recon2025.pdf` | Recon talk. Gives an intro into DBI with DynamoRio |

### Malware-simulation samples (for testing clients)

| Test sample | Description |
| --- | --- |
| `anti_x` | Simulates typical malware obfuscation/anti-analysis behaviors without doing anything malicious. |
| `RelaunchMe` | Restarts itself from the temp directory. |
| `stringdecoder` | Simple decoder for a lightly obfuscated “Hello World!” string. |

---

## Getting started

### Prerequisites
- Install **[DynamoRIO](https://dynamorio.org/page_releases.html)** (Clients were tested with DR 11.3.0)
- Installing DynamoRio is as easy as downloading it and unzipping it to a directory 
- Some test scripts assume to find "drrun.exe" at "C:\tools\DynamoRIO-Windows-11.3.0\bin32\drrun.exe"
- Either make sure you are using the same directory or edit the scripts
- Microsoft Visual Studio 2019 (recommended) or later
- CMAKE (installed with Visual Studio)

### Build 
- We are running and compiling the examples in MSYS2, but it should work in a normal MS Dev Prompt, too
- You can find build scripts named "MSYS_build32.sh" and "MSYS_build64.sh" inside the client directories
- They are building the client DLLs by using CMake. 
- The MSYS_build scripts are mainly launching the MS Dev Prompt and executing a build.bat 
- The Malware simulation examples in "testsamples" can be build with VisualStudio 2019 or later.

### Run client DLLs with DynamoRio
- Start a MSYS2 shell on Windows (all scripts are tested with Windows 11 24H2)
- Most client directories have a "run_tracer32.sh" and "run_tracer64.sh" bash script or similar as an 
  example how to execute the client DLL with a sample target application

### Hints
The different clients have all a similar directory structure. (Not all files exists in all projects) 

For example, let's look at the tracer-memdump directory:

| Doc file | Description |
| --- | --- |
| `bin` | Directory for the client DLL| 
| `build` | temp. build directory |
| `build32.bat` | 32 bit build batch file|
| `build64.bat` | 64 bit build batch file|
| `CMakeLists.txt` | CMAKE file|
| `compile_flags.txt` | optional file for sublime text for syntax highlighting. Save to delete |
| `decode_strings.py` | Python helper script |
| `dump_25-09-24_15-37-34_pid17564.csv` | sample output csv file - project specific |
| `dump_25-09-24_15-39-21_pid1720.csv` | sample output csv file - project specific |
| `dump_25-09-24_16-36-38_pid20080.bin` | sample output bin file - project specific |
| `dump_25-09-24_16-36-43_pid1792.bin` | sample output bin file - project specific |
| `memdump.c` | **client source code file** |
| `MSYS_build32.sh` | **32 bit build script to run in MSYS2** |
| `MSYS_build64.sh` | **64 bit build script to run in MSYS2** |
| `README.txt` | Description and hints |
| `run_tracer32.sh` | example for how to run the 32 bit client |
| `run_tracer32-bin.sh` | example for how to run the 32 bit client in binary mode |
| `run_tracer64.sh` | example for how to run the 64 bit client |
| `run_tracer64-bin.sh` | example for how to run the 32 bit client in binary mode |

If you build your own clients, you might want to copy the tracer-memdump directory as a template.
You just need to change the variables in the CMakeLists.txt file to your DLL and src filename and directories.



