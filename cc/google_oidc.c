#include <iostream>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include <jwt-cpp/jwt.h>
#include <curl/curl.h>

/*

Generates google id_token on GCE instance or with GCP service account json file


apt-get install libcurl4-openssl-dev libssl-dev

git clone https://github.com/Thalhammer/jwt-cpp.git
cd jwt-cpp/cmake
mkdir build
cd build
cmake ../../
make


g++ -std=c++11 -I. -Ijwt-cpp/include -o main -lcrypto -lcurl main.cc

with env or on gce
export GOOGLE_APPLICATION_CREDENTIALS=`pwd`/svc_account.json 
./main https://foo.bar
   eyJhbGciOiJSUzI1NiIsImtpZ

with svc_json file
./main https://foo.bar `pwd`/svc_account.json

*/

using namespace std;

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

int main(int argc, char *argv[])
{

    if (argc == 1 || argc > 3)
    {
        cerr << "usage: " << argv[0] << " <audience> <optional: /path/to/service_account.json>\n";
        exit(EXIT_FAILURE);
    }

    std::string target_audience = argv[1];

    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    curl = curl_easy_init();

    std::string adc_file;

    if (argc == 3)
    {
        adc_file = argv[2];
    }
    else
    {
        char const *adc_env = std::getenv("GOOGLE_APPLICATION_CREDENTIALS");
        if (adc_env != NULL)
        {
            adc_file = std::string(adc_env);
        }
    }

    if (!adc_file.empty())
    {
        //std::cout << "Using ADC File: " << adc_file << std::endl;

        std::ifstream adc_json;
        adc_json.open(adc_file);
        if (adc_json.fail())
        {
            cerr << "Error opening ADC file: " << strerror(errno);
        }
        //std::cout << adc_json.rdbuf();
        stringstream ss;
        ss << adc_json.rdbuf();

        picojson::value v;

        std::string err = picojson::parse(v, ss);
        if (!err.empty())
        {
            cerr << err << std::endl;
        }
        std::string issuer = v.get("client_email").get<string>();
        std::string audience = "https://oauth2.googleapis.com/token";
        std::string rsa_priv_key = v.get("private_key").get<string>();

        auto token = jwt::create()
                         .set_issuer(issuer)
                         .set_type("JWT")
                         .set_issued_at(std::chrono::system_clock::now())
                         .set_audience(audience)
                         .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{100})
                         .set_payload_claim("target_audience", jwt::claim(std::string{target_audience}))
                         .sign(jwt::algorithm::rs256("", rsa_priv_key, "", "notasecret"));

        std::string postData = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + token;

        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, "https://oauth2.googleapis.com/token");
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());

            res = curl_easy_perform(curl);

            if (res != CURLE_OK)
            {
                std::cout << (stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                return -1;
            }
            else
            {
                //std::cout << readBuffer << std::endl;
                picojson::value v;
                std::string err = picojson::parse(v, readBuffer);
                if (!err.empty())
                {
                std:
                    cerr << err << std::endl;
                }
                cout << v.get("id_token").get<string>().c_str() << endl;
            }

            curl_easy_cleanup(curl);
        }
    }
    else
    {
        //std::cout << "Using Metadata Server" << std::endl;
        std::string url = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=" + target_audience + "&format=full";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        struct curl_slist *list = NULL;
        list = curl_slist_append(list, "Metadata-Flavor: Google");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            std::cout << (stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            return -1;
        }
        else
        {
            cout << readBuffer << endl;
        }

        curl_easy_cleanup(curl);
    }
}
