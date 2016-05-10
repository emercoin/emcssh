/*
  handle.c
  Hashtable for EmerCoin PKI for OpenSSH
  Author: Oleg Khovayko, 2014-10-15
*/

/*----------------------------------------------------------------------------*/

#include <emcssh.h>

/*----------------------------------------------------------------------------*/

extern int8_t   g_verbose;
extern int8_t   g_ignore;
extern uint32_t g_recursion;

/*----------------------------------------------------------------------------*/

// Buffer to stopr/print recursive path
char pathbuf[1024] = "#Path=";
char *path_end = pathbuf + 6;

/*----------------------------------------------------------------------------*/

// Handle auth-key or token line
void HandleStr(char *buf) {
  if(g_recursion == 0) {
    if(g_verbose > 0)
      fprintf(stderr, "HandleStr: Reached recursion limit, subtree ignored\n");
    return;
  }
  g_recursion--;
  *path_end++ = '/'; 
  *path_end   = 0;
  if(g_verbose > 1)
    puts(pathbuf);
  char *string = buf, *token;
  while((token = strsep(&string, "|\n\r")) != NULL) {
    if(*token == 0)
      continue;
    int rc = InsertHT(token, 0);
    if(rc == 0) // Key already exist, so was already printed
      continue;
    if(rc < 0) {
      if(g_verbose > 0)
	fprintf(stderr, "HandleStr: No room for insert token %s; increase maxkeys in config file\n", token);
      continue;	
    }
    if(g_ignore && g_verbose > 2)
      printf("#-IGN: %s\n", token);
    // Toke had been inserted, so this is new token
    if(*token == '@') {
      token++;
      char emcval[EMC_VAL_SZ + 8];
      char *saved_path_end = path_end;
      if(g_verbose > 1) {
        uint32_t tok_len = strlen(token);
        if(path_end + tok_len < pathbuf + sizeof(pathbuf)) {
          strcpy(path_end, token);
          path_end += tok_len;
	}
      }
      ReqEmc(token, emcval);
      emcval[EMC_VAL_SZ] = 0; // Set EOLN after possible long buf
      HandleStr(emcval);
      path_end = saved_path_end;
      *path_end = 0;
    } else 
      if(!g_ignore)
        puts(token);
  } // while(token)
  
  *--path_end = 0;
  g_recursion++;
} // HandleStr

/*------------------------------E-N-D-----------------------------------------*/

