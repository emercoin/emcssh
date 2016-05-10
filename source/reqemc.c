/*
  handle.c
  Hashtable for EmerCoin PKI for OpenSSH
  Author: Oleg Khovayko, 2014-10-15
*/

/*----------------------------------------------------------------------------*/

#include <emcssh.h>
#include <jansson.h>
#include <curl/curl.h>

/*----------------------------------------------------------------------------*/

extern int8_t g_verbose;
extern int8_t g_ssl_check;
extern char  *g_emcurl;

/*----------------------------------------------------------------------------*/
// Structure from CURL example - for fetch HTTP data into memory
// http://curl.haxx.se/libcurl/c/getinmemory.html
struct MemoryStruct {
  char *memory;
  size_t size;
};

/*----------------------------------------------------------------------------*/
// Callback from CURL example - for fetch HTTP data into memory
// http://curl.haxx.se/libcurl/c/getinmemory.html
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    if(g_verbose > 1)
      fprintf(stderr, "WriteMemoryCallback: realloc returns NULL");
    return 0;
  }
	     
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
} // WriteMemoryCallback


/*----------------------------------------------------------------------------*/
// Request CoinServer
static json_t *CoinSrvRequest(const char *method, json_t *req_arr, int *errcode) {
  if(g_emcurl == NULL)
    return NULL;

  json_t *js_req = json_object();
  json_object_set_new(js_req, "jsonrpc", json_string("1.0"));
  json_object_set_new(js_req, "id"     , json_string("emcssh"));
  json_object_set_new(js_req, "method" , json_string(method));
  json_object_set_new(js_req, "params" , req_arr);

  char *txt;
  if(g_verbose > 9) {
    txt = json_dumps(js_req, JSON_INDENT(2));
    fprintf(stderr, "CoinSrvRequest: Request to server: %s\n", txt);
    free(txt);
  }

  txt = json_dumps(js_req, JSON_COMPACT);
  json_decref(js_req); // Request is not needed anymore


  struct MemoryStruct chunk;
  bzero(&chunk, sizeof(chunk));

  CURL *curl = curl_easy_init();

  if(curl == NULL) {
    if(g_verbose > 1)
      fprintf(stderr, "CoinSrvRequest: Cannot curl_easy_init()\n");
    return NULL;
  }

  // Setup HTTP header
  struct curl_slist *http_header = curl_slist_append(NULL, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_header);

  // Setup URL
  curl_easy_setopt(curl, CURLOPT_URL, g_emcurl);

  // Setup JSON payload
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, txt);

  /* send all data to this function  */ 
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
     
  /* we pass our 'chunk' struct to the callback function */ 
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
       
  /* some servers don't like requests that are made without a user-agent
   *      field, so we provide one */ 
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "emcssh/0.0.3");

  /* Verify Server Certificate flag */
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, g_ssl_check);

  /* Verify Server Certificate flag */
  if(g_ssl_check == 0) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  }

  // Send request to wallet server
  CURLcode res = curl_easy_perform(curl);

  /* always cleanup */ 
  curl_easy_cleanup(curl);

  /* free the custom headers */ 
  curl_slist_free_all(http_header);

  // Must be free only after curl_easy_perform()
  free(txt);

  if(res != CURLE_OK) {
    if(g_verbose > 1)
      fprintf(stderr, "CoinSrvRequest: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    return NULL;
  }
  
  if(chunk.memory == NULL) {
    if(g_verbose > 1)
      fprintf(stderr, "CoinSrvRequest: No data from the server\n");
    return NULL;
  }

  json_error_t error;
  json_t *resp = json_loads(chunk.memory, 0, &error);

  if(resp == NULL) {
    if(g_verbose > 1)
      fprintf(stderr, "CoinSrvRequest: Cannot parse Server's response, error=%s", error.text);
    free(chunk.memory);
    return NULL;
  }

  free(chunk.memory);
  
  if(g_verbose > 9) {
    txt = json_dumps(resp, JSON_INDENT(2));
    fprintf(stderr, "CoinSrvRequest: Response from server: %s\n", txt);
    free(txt);
  }

  // Check for server error - must be null
  json_t *err = json_object_get(resp, "error");
  if(!json_is_null(err)) {
    if(errcode)
      *errcode = json_integer_value(json_object_get(err, "code"));
    txt = json_dumps(resp, JSON_INDENT(2));
    if(g_verbose > 9)
	fprintf(stderr, "CoinSrvRequest: ERROR in response from server: %s\n", txt);
    free(txt);
    json_decref(resp);
    return NULL;
  }

  return resp;
} // CoinSrvRequest


/*----------------------------------------------------------------------------*/
// Request EmerCoin server for SSH key list
void ReqEmc(const char *key, char *value) {
  json_t *ar_main = json_array();
  // sprintf is OK: key size cannot be more than value size (20K + 8)
  // It can be up to 10K (strbuf), or 20K (whole copy or another value)
  sprintf(value, "ssh:%s", key);
  json_array_append_new(ar_main, json_string(value));

  int retcode = 0;
  json_t *resp = CoinSrvRequest("name_show", ar_main, &retcode);
  *value = 0;

  if(resp == NULL || retcode < 0)
    return; 

  json_t *jo_res = (json_object_get(resp, "result"));

  json_t *jo_val = json_object_get(jo_res, "value");
  if(json_is_string(jo_val)) 
    strncpy(value, json_string_value(jo_val), EMC_VAL_SZ);
  json_decref(resp);
} // ReqEmc
/*------------------------------E-N-D-----------------------------------------*/

