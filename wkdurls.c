#include <glib.h>
#include <gio/gio.h>
#include <errno.h>
#include <locale.h>
#include "zbase32.h"

/* Implementation of OpenPGP Web Key Directory URLs as defined in
 * https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08#section-3.1. */

static char *
ascii_lower(char *in)
{
  GString *tmp;

  g_return_val_if_fail (in != NULL, NULL);
  tmp = g_string_new (in);
  return g_string_free (g_string_ascii_down (tmp), FALSE);
}

static char *
encode_local (const char *local)
{
  g_autoptr(GChecksum) checksum = NULL;
  guint8 digest[20] = { 0 };
  gsize len = sizeof(digest);
  char *encoded;

  g_return_val_if_fail (local != NULL, NULL);

  checksum = g_checksum_new (G_CHECKSUM_SHA1);
  g_checksum_update (checksum, (const guchar *)local, -1);
  g_checksum_get_digest (checksum, digest, &len);

  encoded = zbase32_encode (digest, len);

  /* If the returned string is NULL, then there must have been a memory
   * allocation problem. Just exit immediately like g_malloc.
   */
  if (encoded == NULL)
    g_error ("%s: %s", G_STRLOC, g_strerror (errno));

  return encoded;
}

static gboolean
build_wkd_urls (const char *uid, char **out_advanced_url,
                char **out_direct_url, GError **error)
{
  g_auto(GStrv) uid_parts = NULL;
  g_autofree char *local_lowered = NULL;
  g_autofree char *domain_lowered = NULL;
  g_autofree char *local_encoded = NULL;
  g_autofree char *local_escaped = NULL;
  g_autofree char *advanced_url = NULL;
  g_autofree char *direct_url = NULL;

  g_return_val_if_fail (uid != NULL, FALSE);

  uid_parts = g_strsplit (uid, "@", -1);
  if (g_strv_length (uid_parts) != 2)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "Invalid email address \"%s\"", uid);
      return FALSE;
    }

  local_lowered = ascii_lower (uid_parts[0]);
  g_debug ("Local orig: %s", uid_parts[0]);
  g_debug ("Local converted: %s", local_lowered);

  domain_lowered = ascii_lower (uid_parts[1]);
  g_debug ("Domain orig: %s", uid_parts[1]);
  g_debug ("Domain converted: %s", domain_lowered);

  local_encoded = encode_local (local_lowered);
  g_debug ("Encoded local part: %s", local_encoded);

  local_escaped = g_uri_escape_string (uid_parts[0], NULL, FALSE);
  g_debug ("Escaped local part: %s", local_escaped);

  advanced_url = g_strdup_printf ("https://openpgpkey.%s"
                                  "/.well-known/openpgpkey/"
                                  "%s/hu/%s?l=%s",
                                  uid_parts[1], domain_lowered,
                                  local_encoded, local_escaped);
  g_debug ("Advanced URL: %s", advanced_url);

  direct_url = g_strdup_printf ("https://%s/.well-known/openpgpkey/hu/%s?l=%s",
                                uid_parts[1], local_encoded, local_escaped);
  g_debug ("Direct URL: %s", direct_url);

  if (out_advanced_url != NULL)
    *out_advanced_url = g_steal_pointer (&advanced_url);
  if (out_direct_url != NULL)
    *out_direct_url = g_steal_pointer (&direct_url);

  return TRUE;
}

int main (int argc, char *argv[])
{
  g_autofree char *advanced_url = NULL;
  g_autofree char *direct_url = NULL;
  g_autoptr(GError) error = NULL;

  setlocale (LC_ALL, "");
  g_set_prgname (argv[0]);

  if (argc != 2)
    {
      g_printerr ("error: no email address supplied\n");
      exit (1);
    }

  if (!build_wkd_urls (argv[1], &advanced_url, &direct_url, &error))
    {
      g_printerr ("error: %s\n", error->message);
      exit (1);
    }

  g_print ("Advanced URL: %s\n", advanced_url);
  g_print ("Direct URL: %s\n", direct_url);

  return 0;
}
