#include "otlp.h"
#include <stdio.h>

cJSON_bool addAttributeToObject(cJSON *object, const char *const key, const char *const value)
{
    cJSON *new_attr = createAttibute(key, value);
    cJSON *attr_array = cJSON_GetObjectItem(object, "attributes");
    if (!attr_array)
    {
        attr_array = cJSON_AddArrayToObject(object, "attributes");
    }
    return cJSON_AddItemToObjectCS(attr_array, "attributes", new_attr);
}

cJSON *createAttibute(const char *const key, const char *const stringValue)
{
    cJSON *attr = cJSON_CreateObject();
    cJSON_AddStringToObject(attr, "key", key);
    cJSON *value = cJSON_AddObjectToObject(attr, "value");
    cJSON_AddStringToObject(value, "stringValue", stringValue);
    return attr;
}

cJSON *createSpan(char *traceId, char *spanId, char *parentSpanId, char *name, signed long startTimeUnixNano, unsigned long endTimeUnixNano)
{
    cJSON *span = cJSON_CreateObject();
    cJSON_AddStringToObject(span, "traceId", traceId);
    cJSON_AddStringToObject(span, "spanId", spanId);
    cJSON_AddStringToObject(span, "parentSpanId", parentSpanId);
    cJSON_AddStringToObject(span, "name", name);
    unsigned char s[19], e[19];
    sprintf(s, "%ld", startTimeUnixNano);
    sprintf(e, "%ld", startTimeUnixNano);
    cJSON_AddRawToObject(span, "startTimeUnixNano", s);
    cJSON_AddRawToObject(span, "endTimeUnixNano", e);

    cJSON_AddNumberToObject(span, "kind", 2);
    return span;
}

cJSON *createResource()
{
    cJSON *resource = cJSON_CreateObject();
    addAttributeToObject(resource, "service.name", "otlp.skb");
    return resource;
}

cJSON *createScope()
{
    cJSON *scope = cJSON_CreateObject();
    cJSON_AddStringToObject(scope, "name", "otlp.skb");
    cJSON_AddStringToObject(scope, "version", "1.0.0");
    return scope;
}

struct otlpData createOtlpData()
{
    struct otlpData d;
    d.resourceSpans = cJSON_CreateObject();
    cJSON *resourceSpansArray = cJSON_AddArrayToObject(d.resourceSpans, "resourceSpans");
    cJSON *resourceSpan = cJSON_CreateObject();
    cJSON_AddItemToArray(resourceSpansArray, resourceSpan);
    cJSON_AddItemToObjectCS(resourceSpan, "resource", createResource());
    cJSON *scopeSpansArray = cJSON_AddArrayToObject(resourceSpan, "scopeSpans");
    cJSON *scopeSpan = cJSON_CreateObject();
    cJSON_AddItemToArray(scopeSpansArray, scopeSpan);
    cJSON_AddItemToObjectCS(scopeSpan, "scope", createScope());
    d.spans = cJSON_AddArrayToObject(scopeSpan, "spans");
    return d;
}
cJSON_bool addSpan(struct otlpData *data, cJSON *span)
{
    return cJSON_AddItemToArray(data->spans, span);
}