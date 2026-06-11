# kernel-func-finder

用于检测内核镜像是否包含特定函数的工具
专门验证 Android boot 镜像中的内核级回滚熔断机制是否存在

支持扫描 kernel Image、boot.img、vendor_boot.img、vendor_dlkm.img 及单个 .ko 文件的函数符号
例如 `qcom_scm_update_rollback_version`

部分内核符号解析思路参考自 [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)

英文版见 [README.md](README.md)
