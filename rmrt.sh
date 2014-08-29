#!/bin/bash

echo -n ms > /proc/rtkit
sudo rmmod rt
