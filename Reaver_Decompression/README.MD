![](https://s3.amazonaws.com/u42/unit42.png)

# Reaver Malware Decompressor

First, download the Python script and DLL to a directory of your choosing.  The DLL and Py script must reside in the same current working directory.

Run the Python script from the command line with the following input parameters:  -i name of Reaver binary.  i.e. lzwDecompress.py -i sample.exe

The script will search the provided input file for the magic Reaver signature and if found will attempt to decompress the data to a text file.

An optional parameter is -o outputfile.  If provided the Python script will output the file to the given name otherwise it will create the text file

using the input file name with a dot txt file extension.

Note:  The script currently only runs on Windows  