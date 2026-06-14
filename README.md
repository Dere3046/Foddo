# kernel-func-finder

```
grep "T qcom_scm_update_rollback_version" /proc/kallsyms
```
```
grep "qcom_scm_update_rollback_version" /proc/kallsyms
```
A tool to detect whether a kernel image contains specific functions.
Designed for verifying if kernel-level rollback fuse mechanisms exist in Android boot images.

Scan kernel Image, boot.img, vendor_boot.img, vendor_dlkm.img, or individual .ko files
for function symbols like `qcom_scm_update_rollback_version`.

Some ideas for parsing kernel symbols from [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)

For Chinese version see [README_ZN.md](README_ZN.md)
