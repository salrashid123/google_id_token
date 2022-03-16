#include <iostream>
#include <jwt-cpp/jwt.h>
#include <curl/curl.h>

/*

Extract public/private keyapir from service account p12 file
    openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out private.pem
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
    
apt-get install libcurl4-openssl-dev libssl-dev

git clone https://github.com/Thalhammer/jwt-cpp.git
cd jwt-cpp/cmake
mkdir build
cd build
cmake ../../
make



g++ -std=c++11 -I. -Ijwt-cpp/include -o main -lcrypto -lcurl main.cc
$ ./main 
{"id_token":"eyJhbGciOiJSUzI1NiIsImtpZ

*/

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int main() {
	std::string rsa_priv_key = R"(-----BEGIN RSA PRIVATE KEY-----
MIIttgIEPdKpyQLpR....
-----END RSA PRIVATE KEY-----)";

    auto issuer = "yubikey-svc@foo.iam.gserviceaccount.com";
    auto audience = "https://oauth2.googleapis.com/token";
    auto target_audience = "https://foo.bar";

	auto token = jwt::create()
					 .set_issuer(issuer)
					 .set_type("JWT")
					 .set_issued_at(std::chrono::system_clock::now())
					 .set_audience(audience)
					 .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{100})
					 .set_payload_claim("target_audience", jwt::claim(std::string{issuer}))
					 .sign(jwt::algorithm::rs256("", rsa_priv_key, "", ""));

	//std::cout << "token:\n" << token << std::endl;

    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    std::string postData = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + token;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://oauth2.googleapis.com/token");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,postData.c_str());
    
        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            std::cout <<(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            return -1;
        }
        else
        {
          std::cout << readBuffer << std::endl;          
        }

        curl_easy_cleanup(curl);
    }
}
