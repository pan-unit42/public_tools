#!/usr/bin/env python3
import sys

if __name__ == "__main__":
    #need to do this to handle Python parser as the parser runs first versus code execution
    #older pyhon version will fail and there is no way to catch the exception thrown
    if sys.version_info[0] != 3:
        print("This script requires Python version 3.0 or higher")
        sys.exit(1)
    else:
        import PlugXDecrypter
        PlugXDecrypter.Start()
