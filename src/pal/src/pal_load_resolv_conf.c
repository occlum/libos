#include <stdio.h>
#include <stdlib.h>
#include "pal_log.h"

char *pal_load_resolv_conf(void) {
    FILE *fp = fopen("/etc/resolv.conf", "rb");

    if (fp == NULL) {
        PAL_WARN("Warning: Failed to open /etc/resolv.conf file");
        return NULL;
    } else {
        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        char *resolv_conf_buffer = malloc(fsize + 1);
        if (resolv_conf_buffer == NULL) {
            PAL_WARN("Warning: Failed to malloc for /etc/resolv.conf buffer");
            return NULL;
        }
        fread(resolv_conf_buffer, 1, fsize, fp);
        resolv_conf_buffer[fsize] = 0;
        fclose(fp);
        return resolv_conf_buffer;
    }
}
