# torrentcheck

torrentcheck - catalog a `.torrent` file and optionally verify content hashes.

Usage: `torrentcheck torrent-file [-p content-path] [-n] [-h] [-c] [-d]`

Options:  
`-n` suppresses progress count,  
`-h` shows all hash values,  
`-c` or `-d` uses comma or dot formatted byte counts.

Returns 0 if successful, nonzero return code if errors found.

Option: `-sha1` [optional hash] acts as a simple SHA1 filter.

If `-sha1` is followed by a hex hash, the return code will be zero
on match and nonzero otherwise.

### Summary

This program is a command-line utility to catalog and verify torrent files.
Run with only the -t option, it displays the metadata, name, and size of
each file in the torrent. Run with the -t and -p options, it computes the
hashes of all files in the torrent, compares them against the hashes stored
in the metadata, and warns of any errors.

If torrentcheck returns "torrent is good" at the end of its output, every
byte of every file in the torrent is present and correct, to a high degree of
certainty as explained below.

For example, if you run torrents on a fast external server and then download
the files, this utility will verify that the files you received are complete
and uncorrupted. It can also be used to verify backups or to automatically
check a series of torrents using scripting.

The -t parameter should be the path to the .torrent metadata file. The -p path
should point to the file or files. It can include or leave out the torrent name.
The -n option suppresses the running count, which is useful if you are writing
the output to a file. The -h option shows all piece hash values. The -c or -d
options produce comma or dot formatted byte counts for readability.

The -sha1 option disables torrent checking, and instead acts as a SHA1 filter.
Most Windows machines do not have a SHA1 utility, so I included this mode as a
convenience feature. It reads in binary data from standard input until end of
file, and prints the SHA1 hash. If a SHA1 hash is provided on the command line,
it will return 0 if the hashes match or nonzero if they do not. This mode
should agree with the output of "openssl dgst -sha1" or "digest -a sha1"

### Examples

```shell
torrentcheck \torrents\ubuntu-10.10-desktop-i386.iso.torrent
torrentcheck \torrents\ubuntu-10.10-desktop-i386.iso.torrent -p \download
torrentcheck \torrents\ubuntu-10.10-desktop-i386.iso.torrent -p \download && echo good
torrentcheck \torrents\ubuntu-10.10-desktop-i386.iso.torrent -p \download || echo bad
torrentcheck \torrents\ubuntu-10.10-desktop-i386.iso.torrent -p \download\ubuntu-10.10-desktop-i386.iso
torrentcheck -sha1 < \download\ubuntu-10.10-desktop-i386.iso
torrentcheck -sha1 b28bbd742aff85d21b9ad96bb45b67c2d133be99 < \download\ubuntu-10.10-desktop-i386.iso && echo good
```
(These are for Windows; use forward slashes in Unix/Linux)

### Automation and scripting

Torrentcheck returns 0 in the Unix $? return code or Windows errorlevel
if it successfully verifies a torrent, or nonzero return codes if it fails.

If you have your torrents in `\torrents` and the downloaded files in `\share`,
make a "bad" directory under `\torrents`, cd to `\torrents`, and run:

(Windows)
```shell
for %i in (*.torrent) do torrentcheck "%i" -p \share || move "%i" bad
```

(Linux)
```shell
for i in *.torrent; do torrentcheck "$i" -p /share || mv "$i" bad ; done
```

This will check all the torrents, and move any that are not fully
downloaded and correct into `\torrents\bad`.

Run this command to generate a master list file with the contents of all your
torrents. This file can be searched to find a particular file and which torrent
it comes from.

(Windows)
```shell
for %i in (*.torrent) do torrentcheck "%i" >> masterlist.txt & echo. >> masterlist.txt
```

(Linux)
```shell
for i in *.torrent; do torrentcheck "$i" >> masterlist.txt ; echo >> masterlist.txt ; done
```

### Detailed description

BitTorrent is a file sharing system which uses a metadata file, usually with
the .torrent extension, to identify a data file or group of files. Given the
metadata file, a BitTorrent client can download and share the data files.
It can also verify the integrity of the files.

The metadata file uses an encoding scheme called "bencode" which can store
integers, strings, lists, and key-value pairs. It can represent binary values
without any escaping, so a bencoded string can be loaded into memory and parsed
in place, without any decoding. Torrent metadata contains the names and sizes
of all the files in the torrent, and also contains a series of SHA1 hashes on
each piece of the data file or files. The piece size is specified in the
metadata, ranging from 32KiB (32768) to 4MiB (4194304) in a sample of torrents.

SHA1 is a complex error-checking code designed by the National Security Agency
for the military Defense Messaging System. It inputs an arbitrarily long byte
string and outputs a 20-byte check code. If any bit in the input changes, the
check code will change. SHA1 is complex enough so that even by deliberate
effort it is very difficult to find two strings with the same check code. The
chance of this happening by accident is small enough to ignore.

To check a single-file torrent, allocate a buffer equal to the "piece size"
string in the metadata, open the input file identified by the "name" string
or specified on the command line, and read in pieces one at a time. The last
piece will likely be short; keep track of the number of bytes actually read.
Hash each piece, and compare the hash code against the corresponding hash code
in the metadata. Any mismatch is an error.

To check a multiple-file torrent, allocate a buffer as above. Read files in
order from the "files" list in the metadata and reconstruct the paths, where
the "name" string may be the base directory. Read from each file in sequence
into the buffer until the buffer is full or the last file has been read, then
hash it and check against the list in the metadata. Any mismatch is an error.

Hash pieces span multiple files, so a missing or corrupt file can cause the
previous or next file to fail as well. In particular, a missing file usually
causes the previous and next files to fail verification. This is an artifact of
the torrent format, and there is no way to avoid it. Torrents often contain a
large media file and a small descriptive text file. If the text file is
missing, the media file usually cannot be verified.

Torrentcheck also verifies the length of each file, and flags an error if the
length is wrong even if the hash codes match. It is designed to handle files
over 4GB on a 32-bit machine.

The SHA1 implementation used by torrentcheck was written by David Ireland,
AM Kuchling, and Peter Gutmann. The source code does not contain a copyright
notice, and this file is widely used on the Internet.

### Compiling

There is no makefile. The required `gcc` lines are at the top of the
`torrentcheck.c` source file. The major catch in compiling is making 64-bit file
I/O work. It is tested on Windows, Linux, and Solaris, but you may have to
experiment with compiler options to get 64-bit ftell and fseek working.
