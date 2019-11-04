#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/engine.h>

#include <curl/curl.h>

#include <cjson/cJSON.h>

/*
Acquire Google OpenID Connect (OIDC) token for a Service Account.

To use, edit issuer, subject and target_audience vaules

Service Account key must be in .p12 format:
   https://cloud.google.com/iam/docs/service-accounts

1) Download Service account .p12 file
2) Extract public/private keyapir
    openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out private.pem
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem

5) Compile
    apt-get install libcurl4-openssl-dev libssl-dev

    git clone https://github.com/DaveGamble/cJSON.git
    cd cJSON
    make
    make install

    gcc google_oidc.c -lcrypto -lcjson  -lcurl -o google_oidc

6) Run
     ./google_oidc


Attribuion:
 https://curl.haxx.se/libcurl/c/getinmemory.html
 https://github.com/DaveGamble/cJSON
 https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
 https://incolumitas.com/2012/10/29/web-safe-base64-encodedecode-in-c/
*/

typedef unsigned char byte;

#define UNUSED(x) ((void)x)
const char hn[] = "SHA256";

const char *issuer = "svc-2-429@mineral-minutia-820.iam.gserviceaccount.com";
const char *subject = "svc-2-429@mineral-minutia-820.iam.gserviceaccount.com";
const char *target_audience = "https://foo.bar";
const char *pubfilename = "public.pem";
const char *privfilename = "private.pem";

const char *audience = "https://oauth2.googleapis.com/token";

/* Returns 0 for success, non-0 otherwise */
int sign_it(const byte *msg, size_t mlen, byte **sig, size_t *slen, EVP_PKEY *pkey);

/* Prints a buffer to stdout. Label is optional */
void print_it(const char *label, const byte *buff, size_t len);

#define MAX_B64_PADDING 0x2
#define B64_PAD_CHAR "="

char *Base64Encode(char *input, unsigned int inputLen);

static unsigned char GetIndexByChar(unsigned char c);

const char *b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

void string2ByteArray(char *input, byte *output)
{
  int loop;
  int i;
  loop = 0;
  i = 0;
  while (input[loop] != '\0')
  {
    output[i++] = input[loop++];
  }
}

char *concat(const char *s1, const char *s2)
{
  const size_t len1 = strlen(s1);
  const size_t len2 = strlen(s2);
  char *result = (char *)malloc(len1 + len2 + 1);
  memcpy(result, s1, len1);
  memcpy(result + len1, s2, len2 + 1);
  return result;
}

struct string
{
  char *ptr;
  size_t len;
};

struct MemoryStruct
{
  char *memory;
  size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if (ptr == NULL)
  {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int main(int argc, char *argv[])
{

  CURL *curl;
  CURLcode res;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

  //const char *engine_id = "tpm2tss";  // for TPM, see https://github.com/salrashid123/tpm2_evp_sign_decrypt
  const char *engine_id = "rdrand"; // for default

  //printf("Loading certificates using engine %s.\n", engine_id);

  ENGINE *e;

  ENGINE_load_builtin_engines();

  e = ENGINE_by_id(engine_id);
  if (!e)
  {
    printf("Unable to get Engine:\n");
    return -1;
  }
  if (!ENGINE_init(e))
  {
    printf("Unable to init Engine:\n");
    ENGINE_free(e);
    return -1;
  }

  ENGINE_set_default_ciphers(e);

  OpenSSL_add_all_algorithms();

  EVP_PKEY *vkey, *skey;
  FILE *pubf = fopen(pubfilename, "rb");

  //printf("Loading public key \n");
  vkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);

  FILE *privf = fopen(privfilename, "rb");
  //printf("Loading private key \n");

  // Start default
  skey = PEM_read_PrivateKey(privf, NULL, NULL, NULL);
  // End default

  cJSON *header = cJSON_CreateObject();
  cJSON *alg = NULL;
  cJSON *typ = NULL;
  alg = cJSON_CreateString("RS256");
  cJSON_AddItemToObject(header, "alg", alg);
  typ = cJSON_CreateString("JWT");
  cJSON_AddItemToObject(header, "typ", typ);

  char *jwt_header = cJSON_Print(header);
  //printf("%s", jwt_header);

  cJSON *claims = cJSON_CreateObject();
  long now = time(0);
  long expire_on = now + 3600;

  cJSON *iss = NULL;
  cJSON *sub = NULL;
  cJSON *aud = NULL;
  cJSON *target_aud = NULL;
  cJSON *iat = NULL;
  cJSON *exp = NULL;

  iss = cJSON_CreateString(issuer);
  cJSON_AddItemToObject(claims, "iss", iss);
  sub = cJSON_CreateString(subject);
  cJSON_AddItemToObject(claims, "sub", sub);
  aud = cJSON_CreateString(audience);
  cJSON_AddItemToObject(claims, "aud", aud);
  target_aud = cJSON_CreateString(target_audience);
  cJSON_AddItemToObject(claims, "target_audience", target_aud);
  iat = cJSON_CreateNumber(now);
  cJSON_AddItemToObject(claims, "iat", iat);
  exp = cJSON_CreateNumber(expire_on);
  cJSON_AddItemToObject(claims, "exp", exp);

  char *claims_set = cJSON_Print(claims);
  //printf(".%s\n", claims_set);

  char *b64header = Base64Encode(jwt_header, strlen(jwt_header));
  char *b64claim = Base64Encode(claims_set, strlen(claims_set));

  free(jwt_header);
  free(claims);
  free(claims_set);

  char *jwt = concat(concat(b64header, "."), b64claim);

  int len = strlen(jwt);
  byte msg[len];

  string2ByteArray(jwt, msg);

  byte *sig = NULL;
  size_t slen = 0;

  int rc = sign_it(msg, sizeof(msg), &sig, &slen, skey);
  char *b64sig = Base64Encode((char *)sig, slen);

  OPENSSL_free(sig);
  EVP_PKEY_free(skey);
  EVP_PKEY_free(vkey);
  ENGINE_finish(e);
  ENGINE_free(e);

  char *signedJWT = concat(concat(jwt, "."), b64sig);

  //printf("%s\n", final);

  // ********************************************************************** //

  curl_easy_setopt(curl, CURLOPT_URL, "https://oauth2.googleapis.com/token");
  //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);

  struct MemoryStruct chunk;

  chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
  chunk.size = 0;           /* no data at this point */

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  char *postfields = concat("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer", concat("&assertion=", signedJWT));
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);

  res = curl_easy_perform(curl);

  if (res != CURLE_OK)
  {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
    return -1;
  }
  else
  {
   // printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
  }

  int numBytes = chunk.size;
  char *pChar = (char *)malloc(numBytes);
  for (int i = 0; i < numBytes; i++)
  {
    pChar[i] = chunk.memory[i];
  }

  free(chunk.memory);

  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code == 200 && res != CURLE_ABORTED_BY_CALLBACK)
  {
    cJSON *json = cJSON_Parse(pChar);
    //char *s = cJSON_Print(json);
    //printf("Response JSON: %s", s);
    //free(s);

    const cJSON *id_token = NULL;
    id_token = cJSON_GetObjectItemCaseSensitive(json, "id_token");
    if (cJSON_IsString(id_token) && (id_token->valuestring != NULL))
    {
      printf("%s\n", id_token->valuestring);
    }
    else
    {
      printf("Unable to parse Idtoken response\n");
      return -1;
    }
  }
  else
  {
    printf("Unable to get ID Token Response: %s\n", pChar);
    return -1;
  }

  free(pChar);

  curl_easy_cleanup(curl);
  curl_global_cleanup();
}

int sign_it(const byte *msg, size_t mlen, byte **sig, size_t *slen, EVP_PKEY *pkey)
{
  /* Returned to caller */
  int result = -1;

  if (!msg || !mlen || !sig || !pkey)
  {
    assert(0);
    return -1;
  }

  if (*sig)
    OPENSSL_free(*sig);

  *sig = NULL;
  *slen = 0;

  EVP_MD_CTX *ctx = NULL;

  do
  {
    ctx = EVP_MD_CTX_create();
    assert(ctx != NULL);
    if (ctx == NULL)
    {
      printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    const EVP_MD *md = EVP_get_digestbyname(hn);
    assert(md != NULL);
    if (md == NULL)
    {
      printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    int rc = EVP_DigestInit_ex(ctx, md, NULL);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    size_t req = 0;
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    assert(req > 0);
    if (!(req > 0))
    {
      printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    *sig = (byte *)OPENSSL_malloc(req);

    assert(*sig != NULL);
    if (*sig == NULL)
    {
      printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    *slen = req;
    rc = EVP_DigestSignFinal(ctx, *sig, slen);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
      break; /* failed */
    }

    assert(req == *slen);
    if (rc != 1)
    {
      printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
      break; /* failed */
    }

    result = 0;

  } while (0);

  if (ctx)
  {
    EVP_MD_CTX_destroy(ctx);
    ctx = NULL;
  }

  return !!result;
}

void print_it(const char *label, const byte *buff, size_t len)
{
  if (!buff || !len)
    return;

  if (label)
    printf("%s: ", label);

  for (size_t i = 0; i < len; ++i)
    printf("%02X", buff[i]);

  printf("\n");
}
char *
Base64Encode(char *input, unsigned int inputLen)
{
  char *encodedBuf;
  int fillBytes, i, k, base64StrLen;
  unsigned char a0, a1, a2, a3;
  /* Make sure there is no overflow. RAM is cheap :) */
  base64StrLen = inputLen + (int)(inputLen * 0.45);

  encodedBuf = (char *)calloc(base64StrLen, sizeof(char));
  if (encodedBuf == NULL)
  {
    printf("calloc() failed with error %d\n", errno);
    return NULL;
  }

  fillBytes = 3 - (inputLen % 3); /* Pad until dividable by 3 ! */

  k = 0;
  /* Walk in 3 byte steps*/
  for (i = 0; i < inputLen; i += 3)
  {

    a0 = (unsigned char)(((input[i + 0] & 0xFC) >> 2));
    a1 = (unsigned char)(((input[i + 0] & 0x3) << 4) + ((input[i + 1] & 0xF0) >> 4));
    a2 = (unsigned char)(((input[i + 1] & 0xF) << 2) + ((input[i + 2] & 0xC0) >> 6));
    a3 = (unsigned char)((input[i + 2] & 0x3F));

    encodedBuf[k + 0] = b64alphabet[a0];
    encodedBuf[k + 1] = b64alphabet[a1];
    encodedBuf[k + 2] = b64alphabet[a2];
    encodedBuf[k + 3] = b64alphabet[a3];

    /* Prevents buffer overflow */
    if (i + (3 - fillBytes) == inputLen)
    { /* Check if we pad */
      /* fill byte is either 0, 1 or 2 */
      switch (fillBytes)
      {
      case 0: // do nothing
        break;
      case 1: // last encoded byte becomes pad value
        encodedBuf[k + 3] = *B64_PAD_CHAR;
        break;
      case 2: // last two encoded bytes become pad value
        encodedBuf[k + 2] = *B64_PAD_CHAR;
        encodedBuf[k + 3] = *B64_PAD_CHAR;
        break;
      }
    }
    k += 4;
  }
  return encodedBuf;
}

static unsigned char
GetIndexByChar(unsigned char c)
{
  int i;
  for (i = 0; i < 64; i++)
  {
    if (b64alphabet[i] == c)
      return (unsigned char)i;
  }
  return 100; /* indicates an error */
}