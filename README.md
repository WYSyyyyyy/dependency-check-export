# dependency-check-export
dependency-check报告整理，包括漏洞等级、数量、CVE编号、修复方案

# 背景
此脚本大部分代码由*关东大佬完成。
众所周知，dependency-check是没有修复方案的，本小工具主要是完成结果整理+修复方案，用于交付给客户

# 思路
## 基础信息
在html中获取
## 修复方案
dependency-check的HTML报告没有明显的出处，此处用阿里云的漏洞信息库，https://avd.aliyun.com/detail?id=AVD-xxxx-xxxxx

# 使用说明
## 安装依赖
openpyxl
lxml
requests

## 用法
python dependency-check-export.py xx.html

## 结果
在xx.html同级文件下生成xx.xlsx

# 最后
水平有限，姑且用用吧。
