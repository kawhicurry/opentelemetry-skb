#ifndef OTLP_H
#define OTLP_H

#include "cJSON.h"

struct otlpData
{
    cJSON *resouceSpans; // pointer to root
    cJSON *spans;        // pointer to spans array
};
struct otlpData createOtlpData();
cJSON_bool addSpan(struct otlpData *data, cJSON *span);

cJSON_bool addAttributeFromItemToObject(cJSON *object, cJSON *item);

cJSON *createAttibute(char *key, char *stringValue);
cJSON *createSpan(char *traceId, char *spanId, char *parentSpanId, char *name, unsigned long startTimeUnixNano, unsigned long endTimeUnixNano);

#endif