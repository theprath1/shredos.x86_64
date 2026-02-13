/*
 * installer.c -- ShredOS Vault USB Install Wizard
 *
 * Runs from the ShredOS USB environment:
 *   1. Scans host drives and detects installed OS
 *   2. Walks the user through password/threshold/algorithm setup
 *   3. Copies vault binary and config onto the host drive
 *   4. Hooks into the host boot process (initramfs, LaunchDaemon, etc.)
 *
 * Copyright 2025 -- GPL-2.0+
 */

#include "installer.h"
#include "platform.h"
#include "config.h"
#include "auth_password.h"
#include "wipe.h"
#include "tui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#if defined(VAULT_PLATFORM_LINUX)
  #include <unistd.h>
  #include <sys/stat.h>
  #include <sys/mount.h>
  #include <sys/wait.h>
  #include <dirent.h>
  #include <fcntl.h>
#endif

#define INSTALLER_MNT       "/tmp/vault-probe"
#define INSTALLER_TARGET    "/tmp/vault-target"

/* ------------------------------------------------------------------ */
/*  Helper: run a shell command with printf-style formatting           */
/* ------------------------------------------------------------------ */

static int run_cmd(const char *fmt, ...)
{
    char cmd[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    return system(cmd);
}

/* ------------------------------------------------------------------ */
/*  Helper: check if a file exists under a mount point                 */
/* ------------------------------------------------------------------ */

static int file_exists(const char *base, const char *rel)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", base, rel);
    return access(path, F_OK) == 0;
}

/* ------------------------------------------------------------------ */
/*  Helper: check if a directory exists under a mount point            */
/* ------------------------------------------------------------------ */

static int dir_exists(const char *base, const char *rel)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", base, rel);
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* ------------------------------------------------------------------ */
/*  Helper: read a text field from a file                              */
/* ------------------------------------------------------------------ */

static int read_field(const char *filepath, const char *key,
                       char *out, size_t out_size)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *k = line;
        char *v = eq + 1;

        /* Strip leading/trailing whitespace and quotes */
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t' || *v == '"') v++;
        size_t vlen = strlen(v);
        if (vlen > 0 && v[vlen - 1] == '"') v[vlen - 1] = '\0';

        if (strcmp(k, key) == 0) {
            strncpy(out, v, out_size - 1);
            out[out_size - 1] = '\0';
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Boot USB detection                                                 */
/* ------------------------------------------------------------------ */

static int is_boot_usb(const char *devname)
{
    /* Check if device is removable */
    char rpath[256];
    snprintf(rpath, sizeof(rpath), "/sys/block/%s/removable", devname);
    FILE *fp = fopen(rpath, "r");
    if (!fp) return 0;
    int removable = 0;
    if (fscanf(fp, "%d", &removable) != 1) removable = 0;
    fclose(fp);

    if (!removable) return 0;

    /* Check if our root fs is on this device */
    char cmdline[4096] = {0};
    fp = fopen("/proc/cmdline", "r");
    if (fp) {
        if (fgets(cmdline, sizeof(cmdline), fp))
            ;
        fclose(fp);
    }

    /* If boot device is on this disk, it's probably our USB */
    char devpath[64];
    snprintf(devpath, sizeof(devpath), "/dev/%s", devname);
    if (strstr(cmdline, devpath)) return 1;

    /* Also check by finding where /mnt/shredos or root is mounted */
    return removable; /* Assume removable = ShredOS USB as heuristic */
}

/* ------------------------------------------------------------------ */
/*  OS Detection                                                       */
/* ------------------------------------------------------------------ */

detected_os_t vault_installer_detect_os(const char *partition,
                                         drive_info_t *info)
{
    mkdir(INSTALLER_MNT, 0755);

    /* Try mounting with various filesystem types */
    const char *fstypes[] = {
        "ext4", "ext3", "ext2", "xfs", "btrfs",
        "ntfs3", "ntfs", "vfat", "hfsplus",
        NULL
    };

    int mounted = 0;
    for (int i = 0; fstypes[i]; i++) {
        if (mount(partition, INSTALLER_MNT, fstypes[i],
                  MS_RDONLY | MS_NOEXEC | MS_NOSUID, NULL) == 0) {
            mounted = 1;
            break;
        }
    }

    /* Try ntfs-3g as a fallback (userspace FUSE driver) */
    if (!mounted) {
        if (run_cmd("mount -t ntfs-3g -o ro '%s' '%s' 2>/dev/null",
                     partition, INSTALLER_MNT) == 0)
            mounted = 1;
    }

    if (!mounted) return DETECTED_OS_UNKNOWN;

    detected_os_t os = DETECTED_OS_UNKNOWN;

    /* --- Linux detection --- */
    if (file_exists(INSTALLER_MNT, "etc/os-release")) {
        os = DETECTED_OS_LINUX;

        char osrelease[256];
        snprintf(osrelease, sizeof(osrelease),
                 "%s/etc/os-release", INSTALLER_MNT);

        char name[128] = "Linux";
        char version[64] = "";
        read_field(osrelease, "NAME", name, sizeof(name));
        read_field(osrelease, "VERSION_ID", version, sizeof(version));

        if (version[0])
            snprintf(info->os_name, sizeof(info->os_name),
                     "%s %s", name, version);
        else
            strncpy(info->os_name, name, sizeof(info->os_name) - 1);

        strncpy(info->root_partition, partition,
                sizeof(info->root_partition) - 1);

        info->has_initramfs_tools =
            dir_exists(INSTALLER_MNT, "etc/initramfs-tools");
        info->has_dracut =
            file_exists(INSTALLER_MNT, "usr/bin/dracut") ||
            file_exists(INSTALLER_MNT, "usr/sbin/dracut");
    }
    /* --- macOS detection --- */
    else if (file_exists(INSTALLER_MNT,
                         "System/Library/CoreServices/SystemVersion.plist")) {
        os = DETECTED_OS_MACOS;
        strncpy(info->os_name, "macOS", sizeof(info->os_name) - 1);
        strncpy(info->root_partition, partition,
                sizeof(info->root_partition) - 1);
    }
    /* --- Windows detection --- */
    else if (file_exists(INSTALLER_MNT, "Windows/System32/ntoskrnl.exe") ||
             file_exists(INSTALLER_MNT, "windows/system32/ntoskrnl.exe") ||
             file_exists(INSTALLER_MNT, "WINDOWS/system32/ntoskrnl.exe")) {
        os = DETECTED_OS_WINDOWS;
        strncpy(info->os_name, "Windows", sizeof(info->os_name) - 1);
        strncpy(info->root_partition, partition,
                sizeof(info->root_partition) - 1);
    }

    umount(INSTALLER_MNT);
    info->detected_os = os;
    return os;
}

/* ------------------------------------------------------------------ */
/*  Drive Scanning                                                     */
/* ------------------------------------------------------------------ */

int vault_installer_scan_drives(drive_info_t *drives, int max_drives)
{
    DIR *dir = opendir("/sys/block");
    if (!dir) return 0;

    int count = 0;
    struct dirent *ent;

    while ((ent = readdir(dir)) && count < max_drives) {
        /* Skip virtual devices */
        if (strncmp(ent->d_name, "loop", 4) == 0) continue;
        if (strncmp(ent->d_name, "ram", 3) == 0) continue;
        if (strncmp(ent->d_name, "dm-", 3) == 0) continue;
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        drive_info_t *d = &drives[count];
        memset(d, 0, sizeof(*d));

        snprintf(d->device_path, sizeof(d->device_path),
                 "/dev/%s", ent->d_name);

        /* Get size */
        char spath[256];
        snprintf(spath, sizeof(spath), "/sys/block/%s/size", ent->d_name);
        FILE *sf = fopen(spath, "r");
        if (sf) {
            unsigned long long sectors = 0;
            if (fscanf(sf, "%llu", &sectors) == 1)
                d->size_bytes = sectors * 512ULL;
            fclose(sf);
        }

        /* Skip zero-size devices */
        if (d->size_bytes == 0) continue;

        /* SSD detection */
        d->is_ssd = vault_wipe_is_ssd(d->device_path);

        /* Boot USB detection */
        d->is_boot_usb = is_boot_usb(ent->d_name);

        /* Generate label */
        double gb = (double)d->size_bytes / (1024.0 * 1024.0 * 1024.0);
        snprintf(d->label, sizeof(d->label), "%s (%.1f GB%s%s)",
                 d->device_path, gb,
                 d->is_ssd == 1 ? ", SSD" : (d->is_ssd == 0 ? ", HDD" : ""),
                 d->is_boot_usb ? ", ShredOS USB" : "");

        /* Detect OS on partitions */
        if (!d->is_boot_usb) {
            /* Try the device itself first */
            vault_installer_detect_os(d->device_path, d);

            /* If not found, try partitions */
            if (d->detected_os == DETECTED_OS_UNKNOWN) {
                char pdir[256];
                snprintf(pdir, sizeof(pdir), "/sys/block/%s", ent->d_name);
                DIR *pdd = opendir(pdir);
                if (pdd) {
                    struct dirent *pe;
                    while ((pe = readdir(pdd))) {
                        /* Partition entries look like sda1, nvme0n1p1, etc. */
                        if (strncmp(pe->d_name, ent->d_name,
                                    strlen(ent->d_name)) != 0)
                            continue;
                        if (strcmp(pe->d_name, ent->d_name) == 0)
                            continue;

                        char partdev[256];
                        snprintf(partdev, sizeof(partdev),
                                 "/dev/%s", pe->d_name);

                        vault_installer_detect_os(partdev, d);
                        if (d->detected_os != DETECTED_OS_UNKNOWN)
                            break;
                    }
                    closedir(pdd);
                }
            }
        }

        count++;
    }
    closedir(dir);
    return count;
}

/* ------------------------------------------------------------------ */
/*  Linux Installation                                                 */
/* ------------------------------------------------------------------ */

int vault_installer_install_linux(const drive_info_t *drive,
                                   const vault_config_t *cfg)
{
    mkdir(INSTALLER_TARGET, 0755);

    /* Mount the root partition read-write */
    vault_tui_status("Mounting target filesystem...");

    const char *fstypes[] = {"ext4","ext3","ext2","xfs","btrfs",NULL};
    int mounted = 0;
    for (int i = 0; fstypes[i]; i++) {
        if (mount(drive->root_partition, INSTALLER_TARGET,
                  fstypes[i], 0, NULL) == 0) {
            mounted = 1;
            break;
        }
    }
    if (!mounted) {
        vault_tui_error("Failed to mount %s", drive->root_partition);
        return -1;
    }

    /* Copy vault binary */
    vault_tui_status("Copying vault binary...");
    run_cmd("mkdir -p '%s/usr/sbin'", INSTALLER_TARGET);
    if (run_cmd("cp /usr/bin/shredos-vault '%s/usr/sbin/shredos-vault'",
                INSTALLER_TARGET) != 0) {
        vault_tui_error("Failed to copy vault binary");
        goto fail;
    }
    run_cmd("chmod 755 '%s/usr/sbin/shredos-vault'", INSTALLER_TARGET);

    /* Write config */
    vault_tui_status("Writing configuration...");
    run_cmd("mkdir -p '%s/etc/shredos-vault'", INSTALLER_TARGET);
    run_cmd("chmod 700 '%s/etc/shredos-vault'", INSTALLER_TARGET);
    {
        char cpath[512];
        snprintf(cpath, sizeof(cpath),
                 "%s/etc/shredos-vault/vault.conf", INSTALLER_TARGET);
        if (vault_config_save(cfg, cpath) != 0) {
            vault_tui_error("Failed to write config");
            goto fail;
        }
        run_cmd("chmod 600 '%s'", cpath);
    }

    /* Install boot hooks */
    vault_tui_status("Installing boot hooks...");

    if (drive->has_initramfs_tools) {
        run_cmd("cp /usr/share/shredos-vault/initramfs-hook.sh "
                "'%s/etc/initramfs-tools/hooks/shredos-vault'",
                INSTALLER_TARGET);
        run_cmd("chmod 755 '%s/etc/initramfs-tools/hooks/shredos-vault'",
                INSTALLER_TARGET);
        run_cmd("cp /usr/share/shredos-vault/initramfs-script.sh "
                "'%s/etc/initramfs-tools/scripts/local-top/shredos-vault'",
                INSTALLER_TARGET);
        run_cmd("chmod 755 '%s/etc/initramfs-tools/scripts/local-top/"
                "shredos-vault'", INSTALLER_TARGET);

        /* Rebuild initramfs via chroot */
        vault_tui_status("Rebuilding initramfs (this may take a moment)...");
        run_cmd("mount --bind /dev '%s/dev'", INSTALLER_TARGET);
        run_cmd("mount --bind /proc '%s/proc'", INSTALLER_TARGET);
        run_cmd("mount --bind /sys '%s/sys'", INSTALLER_TARGET);

        int ret = run_cmd("chroot '%s' update-initramfs -u", INSTALLER_TARGET);

        run_cmd("umount '%s/sys' 2>/dev/null", INSTALLER_TARGET);
        run_cmd("umount '%s/proc' 2>/dev/null", INSTALLER_TARGET);
        run_cmd("umount '%s/dev' 2>/dev/null", INSTALLER_TARGET);

        if (ret != 0) {
            vault_tui_error("initramfs rebuild failed");
            goto fail;
        }

    } else if (drive->has_dracut) {
        run_cmd("mkdir -p '%s/usr/lib/dracut/modules.d/90shredos-vault'",
                INSTALLER_TARGET);
        run_cmd("cp /usr/share/shredos-vault/dracut-module/* "
                "'%s/usr/lib/dracut/modules.d/90shredos-vault/'",
                INSTALLER_TARGET);

        vault_tui_status("Rebuilding initramfs (dracut)...");
        run_cmd("mount --bind /dev '%s/dev'", INSTALLER_TARGET);
        run_cmd("mount --bind /proc '%s/proc'", INSTALLER_TARGET);
        run_cmd("mount --bind /sys '%s/sys'", INSTALLER_TARGET);

        int ret = run_cmd("chroot '%s' dracut --force", INSTALLER_TARGET);

        run_cmd("umount '%s/sys' 2>/dev/null", INSTALLER_TARGET);
        run_cmd("umount '%s/proc' 2>/dev/null", INSTALLER_TARGET);
        run_cmd("umount '%s/dev' 2>/dev/null", INSTALLER_TARGET);

        if (ret != 0) {
            vault_tui_error("dracut rebuild failed");
            goto fail;
        }

    } else {
        vault_tui_error("No supported initramfs system on target");
        goto fail;
    }

    vault_tui_status("Finalising...");
    sync();
    umount(INSTALLER_TARGET);
    return 0;

fail:
    run_cmd("umount '%s/sys' 2>/dev/null", INSTALLER_TARGET);
    run_cmd("umount '%s/proc' 2>/dev/null", INSTALLER_TARGET);
    run_cmd("umount '%s/dev' 2>/dev/null", INSTALLER_TARGET);
    umount(INSTALLER_TARGET);
    return -1;
}

/* ------------------------------------------------------------------ */
/*  macOS Installation                                                 */
/* ------------------------------------------------------------------ */

int vault_installer_install_macos(const drive_info_t *drive,
                                   const vault_config_t *cfg)
{
    mkdir(INSTALLER_TARGET, 0755);

    vault_tui_status("Mounting macOS volume...");
    int mounted = 0;
    if (mount(drive->root_partition, INSTALLER_TARGET,
              "hfsplus", 0, NULL) == 0)
        mounted = 1;
    if (!mounted && run_cmd("mount -t hfsplus '%s' '%s' 2>/dev/null",
                             drive->root_partition, INSTALLER_TARGET) == 0)
        mounted = 1;

    if (!mounted) {
        vault_tui_error("Failed to mount macOS volume");
        return -1;
    }

    vault_tui_status("Copying vault binary...");
    run_cmd("mkdir -p '%s/usr/local/sbin'", INSTALLER_TARGET);
    run_cmd("cp /usr/bin/shredos-vault '%s/usr/local/sbin/shredos-vault'",
            INSTALLER_TARGET);
    run_cmd("chmod 755 '%s/usr/local/sbin/shredos-vault'", INSTALLER_TARGET);

    vault_tui_status("Writing configuration...");
    run_cmd("mkdir -p '%s/Library/Application Support/ShredOS-Vault'",
            INSTALLER_TARGET);
    {
        char cpath[512];
        snprintf(cpath, sizeof(cpath),
                 "%s/Library/Application Support/ShredOS-Vault/vault.conf",
                 INSTALLER_TARGET);
        vault_config_save(cfg, cpath);
    }

    vault_tui_status("Installing LaunchDaemon...");
    run_cmd("mkdir -p '%s/Library/LaunchDaemons'", INSTALLER_TARGET);
    run_cmd("cp /usr/share/shredos-vault/com.shredos.vault-gate.plist "
            "'%s/Library/LaunchDaemons/'", INSTALLER_TARGET);

    vault_tui_status("Finalising...");
    sync();
    umount(INSTALLER_TARGET);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Windows Installation                                               */
/* ------------------------------------------------------------------ */

int vault_installer_install_windows(const drive_info_t *drive,
                                     const vault_config_t *cfg)
{
    mkdir(INSTALLER_TARGET, 0755);

    vault_tui_status("Mounting Windows partition...");
    int mounted = 0;
    if (run_cmd("mount -t ntfs-3g '%s' '%s'",
                drive->root_partition, INSTALLER_TARGET) == 0)
        mounted = 1;
    if (!mounted && mount(drive->root_partition, INSTALLER_TARGET,
                           "ntfs3", 0, NULL) == 0)
        mounted = 1;

    if (!mounted) {
        vault_tui_error("Failed to mount NTFS. ntfs-3g required.");
        return -1;
    }

    vault_tui_status("Copying files...");
    run_cmd("mkdir -p '%s/Program Files/ShredOS-Vault'", INSTALLER_TARGET);
    run_cmd("mkdir -p '%s/ProgramData/ShredOS-Vault'", INSTALLER_TARGET);

    /* Copy install scripts for the user to run on Windows */
    run_cmd("cp /usr/share/shredos-vault/windows/* "
            "'%s/Program Files/ShredOS-Vault/' 2>/dev/null",
            INSTALLER_TARGET);

    vault_tui_status("Writing configuration...");
    {
        char cpath[512];
        snprintf(cpath, sizeof(cpath),
                 "%s/ProgramData/ShredOS-Vault/vault.conf", INSTALLER_TARGET);
        vault_config_save(cfg, cpath);
    }

    /* Create README for the user */
    vault_tui_status("Creating setup instructions...");
    {
        char rpath[512];
        snprintf(rpath, sizeof(rpath),
                 "%s/Program Files/ShredOS-Vault/COMPLETE_SETUP.txt",
                 INSTALLER_TARGET);
        FILE *fp = fopen(rpath, "w");
        if (fp) {
            fprintf(fp, "ShredOS Vault - Windows Setup\r\n\r\n");
            fprintf(fp, "Run install.bat as Administrator to complete "
                        "installation.\r\n");
            fprintf(fp, "This registers the Credential Provider and "
                        "starts the vault service.\r\n");
            fclose(fp);
        }
    }

    vault_tui_status("Finalising...");
    sync();
    umount(INSTALLER_TARGET);

    vault_tui_status("NOTE: On Windows, run install.bat as Administrator.");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Install Wizard (main orchestrator)                                 */
/* ------------------------------------------------------------------ */

int vault_installer_run_wizard(void)
{
    vault_config_t cfg;
    vault_config_init(&cfg);

    /* Step 1: Scan drives */
    vault_tui_status("Scanning drives...");

    drive_info_t drives[16];
    int count = vault_installer_scan_drives(drives, 16);

    if (count == 0) {
        vault_tui_error("No target drives found!");
        return -1;
    }

    /* Build labels for the menu */
    const char *labels[16];
    char label_bufs[16][256];

    int selectable_count = 0;
    int selectable_map[16]; /* maps menu index -> drives index */

    for (int i = 0; i < count; i++) {
        if (drives[i].is_boot_usb) continue; /* Skip the ShredOS USB */

        const char *os_str;
        switch (drives[i].detected_os) {
        case DETECTED_OS_LINUX:   os_str = drives[i].os_name; break;
        case DETECTED_OS_MACOS:   os_str = drives[i].os_name; break;
        case DETECTED_OS_WINDOWS: os_str = drives[i].os_name; break;
        default:                  os_str = "Unknown OS"; break;
        }

        double gb = (double)drives[i].size_bytes /
                    (1024.0 * 1024.0 * 1024.0);
        snprintf(label_bufs[selectable_count], sizeof(label_bufs[0]),
                 "%-14s  %6.1f GB  %s%s  [%s]",
                 drives[i].device_path, gb,
                 drives[i].is_ssd == 1 ? "SSD" :
                 (drives[i].is_ssd == 0 ? "HDD" : "   "),
                 drives[i].root_partition[0] ?
                     "" : " (no OS detected)",
                 os_str);

        labels[selectable_count] = label_bufs[selectable_count];
        selectable_map[selectable_count] = i;
        selectable_count++;
    }

    if (selectable_count == 0) {
        vault_tui_error("No target drives found (only ShredOS USB detected)!");
        return -1;
    }

    /* Step 2: User selects target */
    int sel = vault_tui_menu_select(
        "Install ShredOS Vault - Select target drive:",
        labels, selectable_count, 0);

    if (sel < 0) {
        vault_tui_status("Installation cancelled.");
        return -1;
    }

    drive_info_t *target = &drives[selectable_map[sel]];

    if (target->detected_os == DETECTED_OS_UNKNOWN) {
        vault_tui_error("No supported OS detected on %s",
                        target->device_path);
        return -1;
    }

    /* Step 3: Set password */
    char password[256];
    if (vault_tui_new_password(password, sizeof(password)) != 0) {
        vault_tui_status("Installation cancelled.");
        return -1;
    }
    vault_auth_password_hash(password, cfg.password_hash,
                              sizeof(cfg.password_hash));
    vault_secure_memzero(password, sizeof(password));

    /* Step 4: Set failure threshold */
    cfg.max_attempts = vault_tui_set_threshold();

    /* Step 5: Select wipe algorithm */
    cfg.wipe_algorithm = vault_tui_select_algorithm();

    /* Step 6: Set target device */
    strncpy(cfg.target_device, target->device_path,
            sizeof(cfg.target_device) - 1);

    /* Step 7: Confirmation */
    const char *os_label;
    switch (target->detected_os) {
    case DETECTED_OS_LINUX:   os_label = "Linux"; break;
    case DETECTED_OS_MACOS:   os_label = "macOS"; break;
    case DETECTED_OS_WINDOWS: os_label = "Windows"; break;
    default:                  os_label = "Unknown"; break;
    }

    /* Build confirm labels */
    const char *confirm_labels[2] = {"Yes, install", "Cancel"};

    char confirm_title[512];
    snprintf(confirm_title, sizeof(confirm_title),
             "WARNING: Install ShredOS Vault onto %s (%s)?\n"
             "  Drive: %s\n"
             "  OS: %s\n"
             "  Threshold: %d attempts\n"
             "  Wipe: %s\n"
             "  Failed auth WILL WIPE THIS DRIVE!",
             target->device_path, os_label,
             target->label, target->os_name,
             cfg.max_attempts,
             vault_wipe_algorithm_name(cfg.wipe_algorithm));

    int confirm = vault_tui_menu_select(confirm_title, confirm_labels, 2, 1);
    if (confirm != 0) {
        vault_tui_status("Installation cancelled.");
        return -1;
    }

    /* Step 8: Execute installation */
    int ret = -1;
    switch (target->detected_os) {
    case DETECTED_OS_LINUX:
        ret = vault_installer_install_linux(target, &cfg);
        break;
    case DETECTED_OS_MACOS:
        ret = vault_installer_install_macos(target, &cfg);
        break;
    case DETECTED_OS_WINDOWS:
        ret = vault_installer_install_windows(target, &cfg);
        break;
    default:
        vault_tui_error("Unsupported OS.");
        return -1;
    }

    if (ret == 0) {
        vault_tui_status("Installation complete! Remove USB and reboot.");
        /* Wait for keypress */
        vault_tui_menu_select("ShredOS Vault installed successfully!",
                               (const char *[]){"OK - Remove USB and reboot"},
                               1, 0);
    }

    return ret;
}
