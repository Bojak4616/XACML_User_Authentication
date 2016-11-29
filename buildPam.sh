#!/bin/bash

gcc -m64 -fPIC -DPIC -shared -rdynamic -o /lib64/security/first_pam.so first_pam.c

