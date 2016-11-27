#!/usr/bin/python

import os
from time import sleep

if __name__ == '__main__':

    # Pipes faster than writing to disk
    # Create a fresh pipe, deleting anything that was previously in there
    # Limit permissions so that other users can not read the pipe
    path = os.getcwd() + '/pdp_pip'
    print path
    # Try/Except to prevent someone from create a pipe with the same name to DoS
    try:
        os.mkfifo(path, 0600)
    except OSError:
        os.unlink(path)
        os.mkfifo(path, 0600)

    with open(path, 'w') as PIPE:
        PIPE.write("<XML STUFF>")


    sleep(10)
    os.unlink(path)
