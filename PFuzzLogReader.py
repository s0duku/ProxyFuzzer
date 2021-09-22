from PFuzz.Logger import PFuzzLogReader
import sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        exit(0)

    reader = PFuzzLogReader(sys.argv[1])