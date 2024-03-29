#include <iostream>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include <jwt-cpp/jwt.h>
#include <curl/curl.h>

/*

Generates and verifies google id_token on GCE instance or with GCP service account json file

// https://github.com/salrashid123/google_id_token

apt-get install libcurl4-openssl-dev libssl-dev

git clone https://github.com/Thalhammer/jwt-cpp.git
cd jwt-cpp/cmake
mkdir build
cd build
cmake ../../
make


g++ -std=c++11 -I. -Ijwt-cpp/include -o main -lcrypto -lcurl google_oidc.c

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

bool verifyIdToken(std::string token, std::string audience, std::string certsReadBuffer)
{

    auto decoded_jwt = jwt::decode(token);
    picojson::value v;

    std::string err = picojson::parse(v, certsReadBuffer);
    if (!err.empty())
    {
        cerr << err << std::endl;
    }
    picojson::object obj = v.get<picojson::object>();

    // again, we can't use this JWK format of the endpoint
    // since the library i used here for JWK persing looks
    // for the x5c value (which doens't exist)  jwk.get_x5c_key_value();

    // auto jwks = jwt::parse_jwks(certsReadBuffer);
    // auto jwk = jwks.get_jwk(decoded_jwt.get_key_id());
    // auto issuer = decoded_jwt.get_issuer();
    //   jwk does not have an x5c claim so we can't do this stuff here:

    // auto x5c = jwk.get_x5c_key_value();
    // if (!x5c.empty() && !issuer.empty())
    // {
    //     auto verifier =
    //         jwt::verify()
    //             .allow_algorithm(jwt::algorithm::rs256(jwt::helper::convert_base64_der_to_pem(x5c), "", "", ""))
    //             .with_issuer("https://accounts.google.com")
    //             .leeway(60UL); // value in seconds, add some to compensate timeout

    //     verifier.verify(decoded_jwt);
    // }

    // so instead, we're using the PEM format endpoint "https://www.googleapis.com/oauth2/v1/certs";
    // parse that and try to verify using the provided key_id

    for (const auto e : obj)
    {
        // todo:  if the key_id isn't provided, then iterate over all keys and see
        //  if there's a match.  for now, i'm just expecting one to be there in the headers
        //  (which will be the case for google issued tokens)
        if (e.first == decoded_jwt.get_key_id())
        {
            auto verifier =
                jwt::verify()
                    .allow_algorithm(jwt::algorithm::rs256(e.second.get<string>(), "", "", ""))
                    .with_issuer("https://accounts.google.com")
                    .with_audience(audience)
                    .leeway(60UL); // value in seconds, add some to compensate timeout
            std::error_code ec;
            verifier.verify(decoded_jwt, ec);
            if (!ec)
            {
                std::cout << "id_token verified" << endl;
            }
            else
            {
                std::cout << "id_token verification Failed " << ec.message() << endl;
                return false;
            }
        }
    }
    return true;
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

    // download and cache the certs here if you want to
    // test the verification step.
    // google's jwk does not have an x5c claim so we can't use JWK endpoint
    // std::string url = "https://www.googleapis.com/oauth2/v3/certs";

    //  we have to instead use the PEM version here
    std::string url = "https://www.googleapis.com/oauth2/v1/certs";
    std::string certsReadBuffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &certsReadBuffer);
    res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        std::cout << (stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return -1;
    }

    // now generate the id_token
    if (!adc_file.empty())
    {
        // std::cout << "Using ADC File: " << adc_file << std::endl;

        std::ifstream adc_json;
        adc_json.open(adc_file);
        if (adc_json.fail())
        {
            cerr << "Error opening ADC file: " << strerror(errno);
        }
        // std::cout << adc_json.rdbuf();
        stringstream ss;
        ss << adc_json.rdbuf();

        picojson::value v;

        std::string err = picojson::parse(v, ss);
        if (!err.empty())
        {
            cerr << err << std::endl;
        }
        std::string type = v.get("type").get<string>();

        if (type == "service_account")
        {
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
                // std::cout << readBuffer << std::endl;
                picojson::value v;

                std::string err = picojson::parse(v, readBuffer);
                if (!err.empty())
                {
                std:
                    cerr << err << std::endl;
                }
                cout << v.get("id_token").get<string>().c_str() << endl;

                verifyIdToken(v.get("id_token").get<string>(), audience, certsReadBuffer);
            }
            curl_easy_cleanup(curl);
        }
        else if (type == "external_account")
        {
            cerr << "external_account not supported" << std::endl;
            // ref https://blog.salrashid.dev/articles/2022/workload_federation_cloudrun_gcf/
        }
        else
        {
            cerr << "Unknown credential file type  " << type << std::endl;
        }
    }
    else
    {
        // std::cout << "Using Metadata Server" << std::endl;
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
            verifyIdToken(readBuffer, target_audience, certsReadBuffer);
        }
        curl_easy_cleanup(curl);
    }
}
