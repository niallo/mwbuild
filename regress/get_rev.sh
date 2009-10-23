#!/bin/sh

# small wrapper script to reduce ugliness of Makefile

../mw info $(readlink $1) | grep 'Revision: ' | cut -d' ' -f2
