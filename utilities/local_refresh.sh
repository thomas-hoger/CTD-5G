#!/bin/bash
cd /home/oai-5g-cn/Deployments/free5gc/2025/thoger
sudo docker compose down
sudo docker compose up -d
git -C /home/oai-5g-cn/Scripts/branch_guilhem pull
