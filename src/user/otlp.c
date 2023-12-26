#include "otlp.h"

// cJSON *addSpans()
// {
// }

cJSON_bool addAttributeFromItemToObject(cJSON *object, cJSON *item)
{
    cJSON *attr_array = cJSON_GetObjectItem(object, "attributes");
    if (!attr_array)
    {
        attr_array = cJSON_AddArrayToObject(object, "attributes");
    }
    return cJSON_AddItemToObjectCS(attr_array, "attributes", item);
}

cJSON *createAttibute(char *key, char *stringValue)
{
    cJSON *attr = cJSON_CreateObject();
    cJSON_AddStringToObject(attr, "key", key);
    cJSON *value = cJSON_AddObjectToObject(attr, "value");
    cJSON_AddStringToObject(value, "stringValue", stringValue);
    return attr;
}

cJSON *createSpan(char *traceId, char *spanId, char *parentSpanId, char *name, unsigned long startTimeUnixNano, unsigned long endTimeUnixNano)
{
    cJSON *span = cJSON_CreateObject();
    cJSON_AddStringToObject(span, "traceId", traceId);
    cJSON_AddStringToObject(span, "spanId", spanId);
    cJSON_AddStringToObject(span, "parentSpanId", parentSpanId);
    cJSON_AddStringToObject(span, "name", name);
    cJSON_AddNumberToObject(span, "startTimeUnixNano", startTimeUnixNano);
    cJSON_AddNumberToObject(span, "endTimeUnixNano", endTimeUnixNano);

    cJSON_AddNumberToObject(span, "kind", 2);
    return span;
}

// create array of scope spans and return span array for further addition
cJSON *createScopeSpans()
{
    cJSON *scopeSpans = cJSON_CreateObject();
    cJSON *scope = cJSON_AddObjectToObject(scopeSpans, "scope");
    cJSON_AddStringToObject(scope, "name", "otlp.skb");
    cJSON_AddStringToObject(scope, "version", "1.0.0");
    return cJSON_AddArrayToObject(scopeSpans, "spans");
}

cJSON *createResouce()
{
    return cJSON_CreateObject();
}

struct otlpData createOtlpData()
{
    struct otlpData d;
    d.resouceSpans = cJSON_CreateObject();
    d.spans = createScopeSpans();
    cJSON *resourceSpansArray = cJSON_AddArrayToObject(d.resouceSpans, "resouceSpans");
    cJSON *resourceSpan = cJSON_CreateObject();
    cJSON_AddItemToObjectCS(resourceSpan, "scopeSpans", d.spans);
    cJSON_AddItemToObjectCS(resourceSpan, "resource", createResouce());
    cJSON_AddItemToArray(resourceSpansArray, resourceSpan);
    return d;
}
cJSON_bool addSpan(struct otlpData *data, cJSON *span)
{
    return cJSON_AddItemToArray(data->spans, span);
}