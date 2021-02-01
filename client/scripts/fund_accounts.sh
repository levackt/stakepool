#!/bin/bash
docker exec secretdev \
  secretcli tx send a secret1cdycaskx8g9gh9zpa5g8ah04ql0lzkrsxmcnfq 10000000000uscrt -y -b block \
  --keyring-backend test
  