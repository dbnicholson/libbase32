#include <glib.h>
#include "base32.h"

static char *
ascii_lower(char *in)
{
  GString *tmp;

  g_return_val_if_fail (in != NULL, NULL);
  tmp = g_string_new (in);
  return g_string_free (g_string_ascii_down (tmp), FALSE);
}

int main (int argc, char *argv[])
{
  g_autofree char *lowered = NULL;
  g_autoptr(GChecksum) checksum = NULL;
  guint8 digest[20] = { 0 };
  gsize len = sizeof(digest);
  const czstr input = { len, digest };
  zstr out;

  if (argc != 2)
    {
      g_printerr ("error: No ID supplied\n");
      exit (1);
    }

  lowered = ascii_lower (argv[1]);
  checksum = g_checksum_new (G_CHECKSUM_SHA1);
  g_checksum_update (checksum, (const guchar *)lowered, -1);
  g_checksum_get_digest (checksum, digest, &len);

  out = b2a_l (input, sizeof(digest) * 8);
  g_print ("%s\n", out.buf);
  free_z (out);

  return 0;
}
