#! /bin/bash
curl http://mirrors.aliyun.com/repo/Centos-7.repo -O
mv Centos-7.repo /etc/yum.repos.d/Centos-7.repo
sed -i "s/\$releasever/7/g" /etc/yum.repos.d/Centos-7.repo
yum clean all 
yum repolist 