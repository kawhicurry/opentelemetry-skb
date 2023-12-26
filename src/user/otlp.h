#ifndef OTLP_H
#define OTLP_H

#include "cJSON.h"

struct otlpData
{
    cJSON *resourceSpans; // pointer to root
    cJSON *spans;        // pointer to spans array
};
struct otlpData createOtlpData();
cJSON_bool addSpan(struct otlpData *data, cJSON *span);

cJSON_bool addAttributeToObject(cJSON *object, const char *const key, const char *const value);

cJSON *createAttibute(char *key, char *stringValue);
cJSON *createSpan(char *traceId, char *spanId, char *parentSpanId, char *name, signed long startTimeUnixNano, unsigned long endTimeUnixNano);

#endif