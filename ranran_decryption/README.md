![](https://s3.amazonaws.com/u42/unit42.png)

# RanRan Decryption Scripts

First, run the 'collect\_cipher\_streams.exe' against a directory of your choosing. The root drive is recommended in order to increase your odds of identifying possible streams. As an example, run the executable like so:

collect\_cipher\_streams.exe -d C:\ -o streams

This command will look for any suitable streams of various file size ranges, and store them within the streams\ directory. After suitable streams are found, you can then run the 'decrypt\_with\_cipher\_streams.exe' executable.

The 'decrypt\_with\_cipher\_streams.exe' executable requires a folder containing one or more suitable cipher streams. As an example, it can be run like so:

decrypt\_with\_cipher\_streams.exe -d C:\ -i streams

This command will recursively search the C:\ directory looking for any .zXz files. If a cipher stream that corresponds to the file size of the .zXz is present within the streams\ directory, decryption will be attempted. 