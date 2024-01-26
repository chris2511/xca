#!/bin/bash

set -e

default_userid=1000

file_path="/home/user/.Xauthority"

if [ -n "$USER_ID" ]; then
    if [[ "$USER_ID" =~ ^[0-9]+$ ]] && [ "$USER_ID" -gt 0 ]; then
        echo "using USER_ID from environment: $USER_ID"
    else
        echo "USER_ID from environment not numeric, aborting"
        exit 1    
    fi
else
    if [ -e "$filepath" ]; then
        USER_ID=$(stat -c "%u" "$filepath")
        echo "using USER_ID from .Xauthority: $USER_ID"
    else
        USER_ID=$default_userid
        echo "using default USER_ID: $USER_ID"
    fi
fi

useradd -u "$USER_ID" -M -s /bin/bash user

exec su user -c "xca $*"
