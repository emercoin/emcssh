/*
  emcssh.h
  Header for EmerCoin PKI for OpenSSH
  Author: Oleg Khovayko, 2014-10-15
*/

/*----------------------------------------------------------------------------*/

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/*----------------------------------------------------------------------------*/

#define CONFHTSZ	0x100	// Hashtable size for config
#define URANDOM "/dev/urandom"	// Path for Unix rand generator; used in htable.c S_block
#define CF_PATH "/usr/local/etc/emcssh_config" // Path to config file
#define MAX_UN_LEN 500		// Max username length
#define EMC_VAL_SZ (20 * 1024)	// Msz VALUE sise in EMC
#define DEFAULT_AUTH_KEYS "$H/.ssh/emcssh_keys"
#define MAX_RECURSION 30

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
// Initialize HashTable structire for new size
extern int ResetHT(uint32_t htsize);

// Insert key string into hashtable
// Return 1 if inserted, 0 if already exist, -1 if table full
extern int InsertHT(const char *key, uint32_t size);

// Search for key in the hashtable
// Returns pointer to CharPtr, or Ptr to NULL cell, if not found
extern char **LookupHT(const char *key);

// Search for data, assiciated with key in the hashtable
extern char *SearchHT(const char *key); 

// Handle auth-key or token line
extern void HandleStr(char *buf);

// Request EmerCoin server for SSH key list
extern void ReqEmc(const char *key, char *value);

/*------------------------------E-N-D-----------------------------------------*/
