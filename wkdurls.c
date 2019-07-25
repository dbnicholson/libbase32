#include <glib.h>
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

static char *
build_advanced_url (const char *local_original, const char *local_encoded,
                    const char *domain_original, const char *domain_lowered)
{
  g_autofree char *local_escaped = NULL;

  local_escaped = g_uri_escape_string (local_original, NULL, FALSE);

  return g_strdup_printf ("https://openpgpkey.%s/.well-known/openpgpkey/"
                          "%s/hu/%s?l=%s",
                          domain_original, domain_lowered,
                          local_encoded, local_escaped);
}

static char *
build_direct_url (const char *local_original, const char *local_encoded,
                  const char *domain_original)
{
  g_autofree char *local_escaped = NULL;

  local_escaped = g_uri_escape_string (local_original, NULL, FALSE);

  return g_strdup_printf ("https://%s/.well-known/openpgpkey/hu/%s?l=%s",
                          domain_original,local_encoded, local_escaped);
}

int main (int argc, char *argv[])
{
  g_auto(GStrv) uid_parts = NULL;
  g_autofree char *local_lowered = NULL;
  g_autofree char *domain_lowered = NULL;
  g_autofree char *local_encoded = NULL;
  g_autofree char *advanced_url = NULL;
  g_autofree char *direct_url = NULL;

  setlocale (LC_ALL, "");

  if (argc != 2)
    {
      g_printerr ("error: no email address supplied\n");
      exit (1);
    }

  uid_parts = g_strsplit (argv[1], "@", -1);
  if (g_strv_length (uid_parts) != 2)
    {
      g_printerr ("error: invalid email address \"%s\"\n", argv[1]);
      exit (1);
    }

  local_lowered = ascii_lower (uid_parts[0]);
  g_debug ("Local orig: %s", uid_parts[0]);
  g_debug ("Local converted: %s", local_lowered);

  domain_lowered = ascii_lower (uid_parts[1]);
  g_debug ("Domain orig: %s\n", uid_parts[1]);
  g_debug ("Domain converted: %s", domain_lowered);

  local_encoded = encode_local (local_lowered);
  g_debug ("Encoded local part: %s", local_encoded);

  advanced_url = build_advanced_url (uid_parts[0], local_encoded,
                                     uid_parts[1], domain_lowered);
  g_print ("Advanced URL: %s", advanced_url);

  direct_url = build_direct_url (uid_parts[0], local_encoded, uid_parts[1]);
  g_print ("Direct URL: %s", direct_url);

  return 0;
}
