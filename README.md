# SPIF

  `SPIF` is picture encryption technique developed by Elijah Hopp (A.K.A Mr.Zeus), it currently is only avalible as a Python module, but soon(Pre0.2) a CLI will be included.

<h2>How it works</h2>

  `SPIF` takes each pixel of an input file (A picture) converts it into the closest 8-bit color (Only thanks to Pablox-cl), then `SPIF` takes an `end_table`(`Encryption aNd Decryption TABLE`) and converts each pixel into a charater, writing the charater to an output file. Sadly each picture is reduced down to 8-bit color, and runtimes are relatively high, this causes `SPIF` image-encryption to be only sutible for situations where security is the key (Pun very much intended). 
  The Decryption process is simply the above process reversed, minus converting the pixel to closest 8-bit color, and it take each character of an input file rather then pixel... :D

# "SPIF"?

The name "SPIF" is an ode to the Calvin's imaginary charater [Spaceman Spiff][0], from  [Bill Watterson's][1] [Calvin And Hobbes][2].

# How to use SPIF

Before you try to use SPIF you need to a few things, 
- A version of SPIF (We'll get to that later)
- Python 3.X (SPIF has only been tested on 3.6, contact me, or open an issue if you have any trouble running SPIF on another version of Python)
- The image you want to encrypt 
  Now that you have all the dependencies, let's get on to the fun part.
There are two methods to using SPIF, one is using the CLI, which you might perfer if you have a good knowledge of your OS's shell, and the other is using SPIF's Python module functionality, which may come to you more easily if you have used Pyhton before.

<h2>Method one</h2>

  Using the basic functionality of SPIF's command-line interface(CLI) is quite simple, but using SPIF's more complex functionality is more difficut. If you ever get stuck pass the `-h` or `--help` flag to get a full list of flags, and how to structure your commands.

  Let's get started, shall we? First you need SPIF, you can either download it from the Github webpage, or clone it like this: `git clone https://github.com/MrZeusGaming/SPIF-image-encryption/`. Next, you need to navigate into the folder you just downloaded, in a Unix-y shell you do this with the `cd` command, i.e. `cd SPIF-image-encryption`. Now comes the fun part, encrypting your image! To run SPIF all you have to do is this: `<Your Python-calling command> SPIF.py`. Ok, you get an error, don't worry all it should say is something about not pass all required arguments. The reason you were getting the error was because SPIF needs to know a few things before it can do anything; it can't read minds(yet...). These required arguments are: whether you are encrypting or decrypting an image, the path to the input file, and the path to your `end_table` (That stands for `Encryption aNd Decryption TABLE`, didn't read the `How it works` section? I suggest you do, it's a fast, and fun read). You must pass these arguments that exact order. Armed with this knowledge let's try encrypting an image.

```
Elijahs-MacBook:SPIF-image-encryption MrZeus$ ls
DETF.py		LICENSE		SPIF.log
Face_reveal.png	README.md	SPIF.py
Elijahs-MacBook:SPIF-image-encryption MrZeus$ python3.6 SPIF.py encrypt Face_reveal.png DETF.py 
Starting SPIF Pre0.2(https://github.com/MrZeusGaming/SPIF-image-encryption) at 2018-07-14 15:46:48
Processing "Face_reveal.png" with "DETF" as an EnD Tables file.
Your image is 640 pixels by 426 pixels.
The encryption progress has finished.
10.496086 seconds elapsed.

Elijahs-MacBook:SPIF-image-encryption MrZeus$ ls
DETF.py		LICENSE		SPIF.log  Face_reveal.png
README.md	SPIF.py		spif_out.txt
```
  There, now we have the encrypted image file (`spif_out.txt`). Now let's decrypt the image file (`spif_out.txt`):
```
Elijahs-MacBook:SPIF-image-encryption MrZeus$ python3.6 SPIF.py decrypt spif_out.txt DETF.py 
Starting SPIF Pre0.2(https://github.com/MrZeusGaming/SPIF-image-encryption) at 2018-07-14 15:51:37
Processing "spif_out.txt" with "DETF" as an EnD Tables file.
Your encypted image is 640 pixels by 426 pixels.
The decryption progress has finished.
13.242544 seconds elapsed.

Elijahs-MacBook:SPIF-image-encryption MrZeus$ 
```
  And, that's how to use SPIF's CLI.

<h2>Method one</h2>

`COMING SOON`

[0]: https://en.wikipedia.org/wiki/Calvin_and_Hobbes#Calvin's_roles
[1]: https://en.wikipedia.org/wiki/Bill_Watterson
[2]: https://en.wikipedia.org/wiki/Calvin_and_Hobbes
