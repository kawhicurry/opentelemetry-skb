#include <stdio.h>
#include <time.h>
#include <curl/curl.h>

#include "user/otlp.h"
// #include <linux/time.h>

int main()
{
    // prepare data
    struct timespec start, end;
    clock_gettime(CLOCK_REALTIME, &start);
    clock_gettime(CLOCK_REALTIME, &end);
    int64_t start_nano = (int64_t)1000000000UL * (int64_t)start.tv_sec + start.tv_nsec;
    int64_t end_nano = (int64_t)1000000000UL * (int64_t)end.tv_sec + end.tv_nsec;

    struct otlpData d = createOtlpData();
    cJSON *span = createSpan("5B7EFFF798038109D269B073813FC60C", "EEE19B7EC3C1B178",
                             "0000000000000000", "I'm a server span", start_nano, end_nano);
    addAttributeToObject(span, "hello", "world");
    addSpan(&d, span);
    char *data = cJSON_Print(d.resourceSpans);
    printf("%s\n", data);

    // send data
    CURL *curl = curl_easy_init();
    struct curl_slist *header;
    CURLcode res;
    if (!curl)
        return -1;
    header = curl_slist_append(header, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:4318/v1/traces");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    res = curl_easy_perform(curl);
}