#include <emcssh.h>
#include <pwd.h>

/*----------------------------------------------------------------------------*/
char    *g_emcurl  = NULL;
int8_t   g_verbose = 0;			// do not verbose
int8_t   g_ignore  = 1;			// Default flag is ignore
int8_t	 g_ssl_check = 1;		// Check Server's SSL certificate
uint32_t g_recursion = MAX_RECURSION;	// Recursion limit for open tokens
uint32_t g_timio     = DEF_TIMIO;	// Default url connection timeout, secs
/*----------------------------------------------------------------------------*/

int main(int argc, char **argv) {
  // check username presence; if missing, print help
  if(argc == 1) {
    fprintf(stderr, "%s: SSH key retriever from EmerCoin NVS.\n\tRun with parameter <username>\n", argv[0]);
    return 0;
  }

  // Username up to 500 chars; This is enough for most cases
  if(strlen(argv[1]) >= MAX_UN_LEN) {
    fprintf(stderr, "%s: Too long username[%s]; over %d chars\n", argv[0], argv[1], MAX_UN_LEN);
    return -1;
  }

  // 1st stage - read config file
  FILE *conf = fopen(CF_PATH, "r");
  if(conf == NULL) {
    fprintf(stderr, "%s: Cannot open config file %s for read; reason=%s\n", 
            argv[0], CF_PATH, strerror(errno));
    return -1;
  }

  // Reser hashtable for load config keys
  ResetHT(CONFHTSZ);

  char strbuf[10000]; // enough for config line, or SSH key

  while(fgets(strbuf, sizeof(strbuf), conf)) {
    strbuf[sizeof(strbuf) - 2 - MAX_UN_LEN] = 0; // Set EOLN terminal - cut very long line
    // All config keys starts from a letter.
    // So, we can skip all strings, start from special chars
    // No problem if there non-alpha chars - they just will be considered as
    // regular, and key will never retrieved from hashtable.
    if((uint8_t)strbuf[0] < 'A')
      continue; // skip comments, empty lines, etc

    // Remove comment and spaces before comment
    char *eoln = strpbrk(strbuf, "#;!\n\r");
    if(eoln == NULL)
	eoln = strchr(strbuf, 0);
    do {
      *eoln = 0;
    } while((uint8_t)(*--eoln) <= ' ');

    char *key_end = strpbrk(strbuf, " \t");
    if(key_end == NULL)
      continue; // skip singular keys
    *key_end = 0;

    // Need add 2, to skip over \0 at EOLN
    int rc = InsertHT(strbuf, eoln + 2 - strbuf);
    if(rc < 0) {
      fprintf(stderr, "%s: Cannot load key from %s; hasthable overflow\n", argv[0], CF_PATH);
      return -2;
    }
  } // while
  fclose(conf);

  // Config read OK, and deposited into hashtable
  // Extract config keys, and init config variables

  const char *verbose = SearchHT("verbose");
  if(verbose != NULL) 
    g_verbose = atoi(verbose);

  const char *recursion = SearchHT("recursion");
  if(recursion != NULL) 
    g_recursion = atoi(recursion);

  const char *timio = SearchHT("timio");
  if(timio != NULL)
    g_timio = atoi(timio);

  const char *ssl_check = SearchHT("ssl_check");
  if(ssl_check != NULL) 
    g_ssl_check = atoi(ssl_check);

  const char *maxkeys = SearchHT("maxkeys");
  uint32_t max_keys = maxkeys == NULL? 4096 : atoi(maxkeys);

        g_emcurl = SearchHT("emcurl");
  char *ignore   = SearchHT("ignore");

  const char *emcssh_keys_template = SearchHT("emcssh_keys");
  char emcssh_keys[5000], *p;
  strncpy(emcssh_keys, emcssh_keys_template? emcssh_keys_template : DEFAULT_AUTH_KEYS, sizeof(emcssh_keys));
  emcssh_keys[sizeof(emcssh_keys) - 1] = 0; // Set EOLN at the end

  // Resolve $H metasymbol - user's home directory
  if((p = strstr(emcssh_keys, "$H")) != NULL) {
    struct passwd *pwd = getpwnam(argv[1]);
    if(pwd == NULL) {
      fprintf(stderr, "%s: Cannot retrieve HOME dir for user %s\n",
            argv[0], argv[1]);
      return -3;
    }
    *p++ = '%'; *p = 's';
    // strcpy OK, because of sizeof(strbuf) > sizeof(emcssh_keys)
    strcpy(strbuf, emcssh_keys);
    snprintf(emcssh_keys, sizeof(emcssh_keys), strbuf, pwd->pw_dir);
  }

  // Resolve $U metasymbol - username
  if((p = strstr(emcssh_keys, "$U")) != NULL) {
    *p++ = '%'; *p = 's';
    // strcpy OK, because of sizeof(strbuf) > sizeof(emcssh_keys)
    strcpy(strbuf, emcssh_keys);
    snprintf(emcssh_keys, sizeof(emcssh_keys), strbuf, argv[1]);
  }

  if(g_verbose > 0)
    printf("#INFO: verbose=%u; maxkeys=%u recursion=%u emcssh_keys=%s; emcurl=<username:password>%s\n\n", 
	  g_verbose, max_keys, g_recursion, emcssh_keys, strchr(g_emcurl, '@'));

  // Config reading completed
  // Process strings from authorized_keys 

  // Open authorized_keys for this user
  FILE *auth_key = fopen(emcssh_keys, "r"); 
  if(auth_key == NULL) {
    fprintf(stderr, "%s: Cannot open authorized_keys file %s for read; reason=%s\n", 
            argv[0], emcssh_keys, strerror(errno));
    return -4;
  }

  if(ignore != NULL)
    ignore = strdup(ignore);

  if(g_emcurl != NULL)
    g_emcurl = strdup(g_emcurl);

  // Reset hash table for used key cache
  ResetHT(max_keys);

  // Fill hashtable with ignored items
  if(ignore) {
    if(g_verbose > 2)
      printf("# ****** IGNORE START ******\n# [%s]\n", ignore);
    HandleStr(ignore);
    free(ignore);
    if(g_verbose > 2)
      printf("# ******IGNORE END ******\n\n");
  }

  g_ignore = 0;

  // Process strings from emcssh_keys
  // Strings can contains comments, keys or lists
  while(fgets(strbuf, sizeof(strbuf), auth_key)) 
    // Token list can start from a letter (key) or from '@' (reference)
    // all another lines - just comments.
    // No problem if there non-alpha chars - they just will be considered as
    // regular
    if((uint8_t)strbuf[0] < '@')
      fputs(strbuf, stdout); // comments, empty or undef lines
    else
      HandleStr(strbuf); // Real list - keys|references
  
  fclose(auth_key);

  // Don't free g_emcurl before exit
  // OS release memory at exit once

  return 0;
} // main

/*------------------------------E-N-D-----------------------------------------*/

