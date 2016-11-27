#!/usr/bin/python

import os

if __name__ == '__main__':

    path = os.getcwd() + '/pdp_pip'
    PIPE = open(path, 'r')
    a = ""
    while True:
        a = PIPE.read()
        print a
        if a:
            break

    print "Done"
