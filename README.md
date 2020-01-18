# Zipper, a CobaltStrike file and folder compression utility.
This CobaltStrike tool allows Red teams to compress files and folders from local and UNC paths. This could be useful in situations where large files or folders need to be exfiltrated. After compressing a file or folder a random named zipfile is created within the user temp folder.

## Usage:

```
Download the Zipper folder and load the Zipper.cna script within the Cobalt Strike Script Manager.
Syntax within beacon context: zipper [Full/UNC path]
```

```
This project is written in C using Visual Studio 2015.
You can use Visual Studio to compile the reflective dll from source.
```
## Note to Blue Teams/Hunters/Defenders:
Lookout for random named zipfiles being created within user temp folders by non file-compression related processes.

## Acknowledgments
[zlib](https://zlib.net/) Compression Library: written by Mark Adler and Jean-loup Gailly.

[Gilles Vollant](https://www.winimage.com/zLibDll/minizip.html): developer of Minizip, which this tool is based on.

## Credits
Author: Cornelis de Plaa (@Cneelis) / Outflank
