#!/bin/bash

find $1 -depth -name '*.dmp' -print -exec rm {} \;
