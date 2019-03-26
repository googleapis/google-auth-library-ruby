#!/bin/bash

script_url="https://raw.githubusercontent.com/googleapis/google-cloud-ruby/master/.kokoro/windows.sh"
curl -o master-windows.sh $script_url && source master-windows.sh
