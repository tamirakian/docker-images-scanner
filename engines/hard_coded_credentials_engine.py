from datetime import datetime

_HARD_CODED_CRED_START = "--BEGIN RSA PRIVATE KEY--"
_HARD_CODED_CRED_END = "--END RSA PRIVATE KEY--"


class HardCodedCredentialsEngine:
    """An Engine for detecting 'Hard-Coded RSA Credentials' pattern"""

    def __init__(self):
        self.__is_cred_start = False

    def credentials_scan(self, file_path):
        print(str(datetime.now()) + " - Scanning - " + file_path)
        with open(file_path, 'r', errors='ignore') as f:
            while True:
                line = f.readline()
                if not line:
                    break
                if _HARD_CODED_CRED_START in line:
                    self.__is_cred_start = True
                    # handling the case the _HARD_CODED_CRED_END appears before the _HARD_CODED_CRED_START
                    line = line.split(_HARD_CODED_CRED_START, 1)[1]
                if _HARD_CODED_CRED_END in line and self.__is_cred_start:
                    return "VULNERABLE", "Files contain hard-coded private keys", file_path

        return "BENIGN", None, None
