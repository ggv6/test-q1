#include <cpprest/http_listener.h>
#include <cpprest/json.h>

#include <iostream>
#include <iomanip>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <chrono>
#include <map>
#include <string>
#include <codecvt>

#include <openssl/sha.h>

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace std;
using namespace chrono_literals;


// declare an alias
using StringMap = map<string, string>;

// Define 2 maps to hold all our entries
// this will allow searching for string or hash
// as the data held is only a string we keep a copy
// if data was larger we would hold just a reference to object
// instances
StringMap _sha256Entries;
StringMap _stringEntries;

// returns an SHA256 hash from a string
// uses openssl to generate it
string getSha256Hash(const string& input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    // initialize update and finalize the hash
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    // convert the bytes into a hexadecimal string
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

// callback/handler function for get requests
void getCallback(http_request request)
{
    ucout << "Received request: " << request.to_string() << std::endl;

    auto answer = json::value::object();

    auto paths = http::uri::split_path(http::uri::decode(request.relative_uri().path()));

    bool handled = false;
    for (utility::string_t reqString : paths)
    {    
        if (!reqString.empty())
        {
            auto iter = _sha256Entries.find(reqString);

            if (iter != _sha256Entries.end())
            {
                answer["message"] = json::value::string(iter->second);
                handled = true;
                break;
            }
            else
                break;
        }
    }
 
    if (!handled)
        answer["err_msg"] = json::value::string("Message not found");

    request.reply(status_codes::OK, answer);
}

// callback/handler function for post requests
void postCallback(http_request request)
{
    ucout << "Received request: " << request.to_string() << std::endl;


    auto answer = json::value::object();
 
    // extract and inspect the json received
    request
        .extract_json()
        .then([&answer](pplx::task<json::value> task) {
            try
            {
                auto const & jvalue = task.get();

                if (!jvalue.is_null())
                {

                    auto obj = jvalue.as_object();

                    auto msgValue = obj.at("message");

                    // extract the string
                    auto reqString = msgValue.as_string();

                    // check in case we already have it
                    auto iter = _stringEntries.find(reqString);
                    string hash;

                    if (iter == _stringEntries.end()) 
                    {
                        wcout << L"New message add it to the map" << std::endl;
                        hash = getSha256Hash(reqString);

                        // add it to the map if not already there
                        _sha256Entries.insert(StringMap::value_type(hash, reqString));
                        _stringEntries.insert(StringMap::value_type(reqString, hash));
                    }
                    else 
                    {
                        wcout << L"Messge already in the map" << std::endl;

                        hash = iter->second;
                    }
                    answer["digest"] = json::value::string(hash); 
                }
            }
            catch (http_exception const & e)
            {
                wcout << e.what() << endl;
            }
        })
      .wait();
 
   request.reply(status_codes::OK, answer);
}

// Creates a new service using the CPP rest sdk.
// It registers callbacks for get and post and handles
// the user requests.
int main(int argc, char** argv)
{
    try
    {
        cout << "Creating local messages service" << endl;

        // a new listener for our service on localhost inteface
        http_listener service("http://*:9000/messages");

        // add callbacks for the methods we support
        service.support(methods::GET,  getCallback);
        service.support(methods::POST, postCallback);

        // initialize the service
        service.open().then([&service]() 
                            {
                                cout << "starting to listen" << std::endl;
                            }
                         ).wait();
 
        // do nothing until the service exits
        while (true) {
            this_thread::sleep_for(10s);    
        }

        cout << "service exited" << std::endl;
   }
   catch (exception const & e)
   {
      cout << e.what() << endl;
   }
 
    return 0;
}
