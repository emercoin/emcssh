/*
  htable.c
  Hashtable for EmerCoin PKI for OpenSSH
  Author: Oleg Khovayko, 2014-10-15
*/

/*----------------------------------------------------------------------------*/

#include <emcssh.h>

/*----------------------------------------------------------------------------*/
// There is single hashtable per program, so will be used global variables
// to keep htable structures

static char	**hashtable = NULL;	// Pointer to hashtable
static uint32_t htmask;			// Hashtable mask
static uint32_t htlimit;	 	// Entries quantity limit

uint32_t S_block[0x100];		// Substitute block for universal hashing

#define NLF(h, c) (S_block[(unsigned char)(c + h)] ^ c)
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))	

extern int etext;

/*----------------------------------------------------------------------------*/
// Initialize HashTable structire for new size
int ResetHT(uint32_t htsize) {
  if(hashtable) {
    // cleanup old hashtable, don't refresh S-block
    uint32_t i;
    for(i = 0; i <= htmask; i++)
      free(hashtable[i]);
    // Delete previous table, if exist. Non-deleted entries will be leaked
    free(hashtable);
  } else {
    // Init S-block
    int fdrnd = open(URANDOM, O_RDONLY);
    if(fdrnd < 0) {
      // Cannot open /dev/urandom, will use own binary code
      memcpy(S_block, &etext, sizeof(S_block));
    } else {
      // Fill S-block with random values
      read(fdrnd, S_block, sizeof(S_block));
      close(fdrnd);
    }
  }

  // Compute real 2^N size in htmask
  for(htmask = 8; htmask < htsize; htmask <<= 1);

  // Allocate a new hashtable
  hashtable = (char **)calloc(htmask, sizeof(char *));
  if(hashtable == NULL) {
    fprintf(stderr, "InitHT: Cannot calloc(%u) pointerd for hashtable\n", htmask);
    return -2; // No memory for hashtable
  }

  // Max htable population is 7/8
  htlimit = htmask - (htmask >> 3);

  // Create real mask
  --htmask;

  return htlimit;
} // InitHT

/*----------------------------------------------------------------------------*/
// Insert key string into hashtable
// Return 1 if inserted, 0 if already exist, -1 if table full
int InsertHT(const char *key, uint32_t size) {
  if(htlimit == 0)
    return -1; // No room to insert new key

  char **insert_point = LookupHT(key);
  if(*insert_point != NULL)
    return 0; // Key already exist

  *insert_point = size? (char *)malloc(size) : strdup(key);

  if(*insert_point == NULL)
    return -1; // No room to insert new key

  if(size)
    memcpy(*insert_point, key, size);

  htlimit--;
  return 1;
} // InsertHT

/*----------------------------------------------------------------------------*/
// Search for data, assiciated with key in the hashtable
char *SearchHT(const char *key) {
  char *rc = *LookupHT(key);
  if(rc != NULL) {
    rc = strchr(rc, 0);
    do {
	++rc;
    } while(*rc <= ' ' && *rc != 0);
  }
  return rc;
} // SearchHT

/*----------------------------------------------------------------------------*/
// Search for key in the hashtable
// Returns pointer to CharPtr, or Ptr to NULL cell, if not found
char **LookupHT(const char *key) {
  // Values step, pos for double hashing
  uint32_t pos  = 0x1F351F35; // Barker code * 2
  uint32_t step = 0x8F1BBCDC; // 2^30 * sqrt(5)

  uint8_t i = 0;
  do {
    char c = key[i];
    if(c == 0)
      break; // End if EOLN
    pos  = ROL(pos , 3) + NLF(step, c);
    step = ROL(step, 5) + NLF(pos,  c); 
  } while(++i); // compute hashes for 256-chars string prefix

  step += step >> 16;
  pos  ^= pos  >> 16;
  step |= 1;

  char **rc;
  do {
    pos = (pos + step) & htmask;
    rc = hashtable + pos;
  } while(*rc != NULL && strcmp(*rc, key));

  return rc;
} // LookupHT


/*------------------------------E-N-D-----------------------------------------*/

