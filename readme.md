## StinkyLoader

This project is my WIP implementation of a reflective loader written in C++ based on the works from:

* https://github.com/fancycode/MemoryModule
* https://github.com/monoxgas/sRDI

Except mine stinks.

Features:
* PE/Rich/NT headers overwritten with random data
* Custom XOR key for payload-module encoding
* Hash-based API resolving
* Native API only

Description:

StinkyLoader - C++ implementation of a reflective loader.

LoaderTester - C++ project to aid in testing the loader during development.

Build steps:

Build project in release mode in VS (I use 2019).

Run the provided python script to extract the loader shellcode and prepend to your target dll.

` python .\Python\generate.py -o <OUTPUT_FILE> -f <TARGET_DLL>.dll -pe .\x64\Release\StinkyLoader.exe -sct .shlc -xor <YOUR_HEX_XOR_KEY_HERE> --dump-shellcode <SHELLCODE_BLOB_OUTPUT_HERE>`

To debug / test your own reflective loader, you can run the LoaderTester with one of the following arguments:

`xload <PAYLOAD_DLL>.dll ` - reflectively load the payload by executing the PIC loader 

`rload <PAYLOAD_DLL>.dll` - reflectively load the dll by testing the `load` function in StinkyLoader

Todos:

* Add API unhooking
  * Implement with SysWhyspers
  * Uh, I was supposed to finish this before pushing to github and making the repo public but uh....
  * Uh......
