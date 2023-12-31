#include <stdio.h>
#include "otlp.h"

int main()
{
    printf("Hello,world\n");
    cJSON *attr = createAttibute("123", "455");
    cJSON *span = createSpan("5B8EFFF798038103D269B633813FC60C", "EEE19B7EC3C1B174", "EEE19B7EC3C1B173", "I'm a server span", 1544712660000000000, 154471266100000000);
    cJSON *attr_array = cJSON_AddArrayToObject(span, "attributes");
    cJSON_AddItemToArray(attr_array, attr);
    cJSON *attr1 = createAttibute("123", "455");
    addAttributeFromItemToObject(span, attr1);

    struct otlpData d = createOtlpData();
    addSpan(&d, span);
    char *s = cJSON_Print(d.resouceSpans);
    cJSON_Delete(span);
    printf("%s\n", s);
}