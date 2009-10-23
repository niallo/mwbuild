#!/bin/sh
# Execute a command with the environment set to output of mw query.
# Assumes you only have one project.
CMD=$@
x=`mw query | grep = | tr '\n' ' ' | sed -e "s,\(.*\),env \1 ,g"`
sh -c "$x $CMD"
