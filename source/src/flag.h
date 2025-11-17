#ifndef FLAG_H
#define FLAG_H

#include <stdio.h>
#include <err.h>

// For compile-time embedding during build
#ifndef FLAG
static char FLAG_BUF[1024];

static void load_flag(void) {
  FILE *fp = fopen("flag", "r");
  if (!fp)
    err(1, "Failed to locate the flag file!");

  size_t len = fread(FLAG_BUF, 1, sizeof(FLAG_BUF)-1, fp);
  FLAG_BUF[len] = '\0';
  fclose(fp);
}

#define FLAG (FLAG_BUF[0] ? FLAG_BUF : (load_flag(), FLAG_BUF))
#endif

#endif /* FLAG_H */
